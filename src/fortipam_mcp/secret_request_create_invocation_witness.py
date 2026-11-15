"""Private producer evidence of the authenticated original create invocation.

The verification key is independently supplied by protected composition, never
loaded from the record. A valid witness alone grants no execution authority.
Consumers must join it to the durable create claim and original parent sources.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import stat
from typing import Any, Protocol

from v4_planning.models import require_digest, require_ref
from .secret_request_collection_http_transport import SecretRequestCollectionRecord
from .secret_metadata_http_transport import _skip_json_space, _json_value_end, _zeroize_mutable
from .secret_approval_build29_http_transport import _raw_members, _validate_ack_json

_CONTRACT = "fortipam-secret-request-create-invocation-witness-v2"
_UNAVAILABLE = "Original create invocation witness is unavailable."
_MAX_BYTES = 8192


class SecretRequestCreateInvocationWitnessError(ValueError):
    """Non-disclosing witness failure."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestCreateInvocationWitness:
    intent_ref: str
    requester_digest: str
    transport_digest: str
    fortipam_requester: str
    environment_ref: str
    scope_ref: str
    created_record: SecretRequestCollectionRecord
    create_started_at: float
    create_finished_at: float
    create_claim_digest: str

    def __post_init__(self) -> None:
        try:
            for value in (self.intent_ref, self.environment_ref, self.scope_ref):
                require_ref(value, "reference")
            for value in (self.requester_digest, self.transport_digest, self.create_claim_digest):
                require_digest(value, "digest")
            if (type(self.fortipam_requester) is not str or not self.fortipam_requester
                    or self.fortipam_requester != self.fortipam_requester.strip()
                    or len(self.fortipam_requester.encode()) > 128
                    or any(ord(c) < 32 or ord(c) == 127 for c in self.fortipam_requester)):
                raise ValueError
            record = self.created_record
            if type(record) is not SecretRequestCollectionRecord:
                raise ValueError
            for identifier in (record.request_id, record.secret_id):
                if type(identifier) is not int or not 0 < identifier <= 2_147_483_647:
                    raise ValueError
            if record.request_type not in ("launcher", "job"):
                raise ValueError
            creation = record.creation_time
            if not ((type(creation) is int and creation > 0) or
                    (type(creation) is str and 0 < len(creation) <= 64
                     and all(32 <= ord(c) < 127 for c in creation))):
                raise ValueError
            for timestamp in (self.create_started_at, self.create_finished_at):
                if type(timestamp) not in (int, float) or not math.isfinite(timestamp) or timestamp <= 0:
                    raise ValueError
            if self.create_finished_at < self.create_started_at:
                raise ValueError
        except (TypeError, ValueError, AttributeError, OverflowError):
            raise SecretRequestCreateInvocationWitnessError(_UNAVAILABLE) from None


class SecretRequestCreateInvocationWitnessSink(Protocol):
    def assert_available(self) -> None: ...
    def publish(self, witness: SecretRequestCreateInvocationWitness) -> None: ...


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


class OwnerOnlySecretRequestCreateInvocationWitnessStore:
    """Bounded owner-only signed immutable file, with atomic no-replace publish."""

    __slots__ = ("_path", "_key")

    def __init__(self, path: Path, verification_key: bytes) -> None:
        self._path = Path(path)
        if (not self._path.is_absolute() or ".." in self._path.parts
                or type(verification_key) is not bytes or len(verification_key) != 32):
            raise SecretRequestCreateInvocationWitnessError(_UNAVAILABLE)
        self._key = verification_key

    def _parent(self) -> int:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in self._path.parent.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise OSError
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def assert_available(self) -> None:
        parent = None
        try:
            parent = self._parent()
            try:
                os.stat(self._path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise OSError
        except OSError:
            raise SecretRequestCreateInvocationWitnessError(_UNAVAILABLE) from None
        finally:
            if parent is not None:
                os.close(parent)

    def publish(self, witness: SecretRequestCreateInvocationWitness) -> None:
        parent = None
        temporary = None
        published = False
        try:
            if type(witness) is not SecretRequestCreateInvocationWitness:
                raise ValueError
            witness.__post_init__()
            payload = {"contract": _CONTRACT, **asdict(witness)}
            signature = hmac.new(self._key, _canonical(payload), hashlib.sha256).hexdigest()
            content = _canonical({"payload": payload, "hmac_sha256": signature})
            if not 0 < len(content) <= _MAX_BYTES:
                raise ValueError
            parent = self._parent()
            name = f".invocation-{secrets.token_hex(16)}"
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            temporary = name
            try:
                view = memoryview(content)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError
                    view = view[count:]
                os.fsync(fd)
                info = os.fstat(fd)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode):
                    raise OSError
            finally:
                os.close(fd)
            os.link(name, self._path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            published = True
            os.unlink(name, dir_fd=parent)
            temporary = None
            os.fsync(parent)
        except (OSError, ValueError, TypeError, OverflowError):
            if published and parent is not None:
                try:
                    os.unlink(self._path.name, dir_fd=parent)
                    os.fsync(parent)
                except OSError:
                    pass
            raise SecretRequestCreateInvocationWitnessError(_UNAVAILABLE) from None
        finally:
            if parent is not None:
                if temporary is not None:
                    try:
                        os.unlink(temporary, dir_fd=parent)
                    except OSError:
                        pass
                os.close(parent)

    def load(self) -> SecretRequestCreateInvocationWitness:
        parent = None
        try:
            parent = self._parent()
            fd = os.open(self._path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                        or not 0 < info.st_size <= _MAX_BYTES):
                    raise ValueError
                raw = os.read(fd, _MAX_BYTES + 1)
                if len(raw) != info.st_size:
                    raise ValueError
            finally:
                os.close(fd)
            _validate_raw_schema(raw)
            record = json.loads(raw, object_pairs_hook=_pairs)
            if type(record) is not dict or set(record) != {"payload", "hmac_sha256"}:
                raise ValueError
            payload = record["payload"]
            signature = hmac.new(self._key, _canonical(payload), hashlib.sha256).hexdigest()
            if type(record["hmac_sha256"]) is not str or not hmac.compare_digest(signature, record["hmac_sha256"]):
                raise ValueError
            if type(payload) is not dict or payload.pop("contract") != _CONTRACT:
                raise ValueError
            payload["created_record"] = SecretRequestCollectionRecord(**payload["created_record"])
            return SecretRequestCreateInvocationWitness(**payload)
        except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise SecretRequestCreateInvocationWitnessError(_UNAVAILABLE) from None
        finally:
            if parent is not None:
                os.close(parent)


def _validate_raw_schema(raw: bytes) -> None:
    """Reject unknown/nested fields before decoding any protected values."""
    buffer = bytearray(raw)
    def object_fields(start: int, end: int, expected: set[str], level: int) -> None:
        if buffer[start] != 123:
            raise ValueError
        names: set[str] = set()
        for name, _, left, right, _ in _raw_members(buffer, start, end):
            if name not in expected or name in names:
                raise ValueError
            names.add(name)
            if level == 0 and name == "payload":
                object_fields(left, right, {field.name for field in fields(SecretRequestCreateInvocationWitness)} | {"contract"}, 1)
            elif level == 1 and name == "created_record":
                object_fields(left, right, {field.name for field in fields(SecretRequestCollectionRecord)}, 2)
            elif buffer[left] in (123, 91):
                raise ValueError
        if names != expected:
            raise ValueError
    try:
        start = _skip_json_space(buffer, 0)
        end = _json_value_end(buffer, start)
        if _skip_json_space(buffer, end) != len(buffer):
            raise ValueError
        _validate_ack_json(buffer, start, end)
        object_fields(start, end, {"payload", "hmac_sha256"}, 0)
    finally:
        _zeroize_mutable(buffer)
