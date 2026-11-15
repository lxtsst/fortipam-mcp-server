"""Private write-once Web creation record, not ownership or deletion authority.

Only the fixed reader can supply the first record. Reload verifies its seal and
the original signed M4 terminal without rebuilding the transient HTTP observation
or acquiring material. No record can be imported from a caller-provided payload.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import cast
import uuid

from v4_planning import canonical_digest

from .mutable_json_buffer import _take_mutable_prefix
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_approval_build29_runtime_provider import _read_private_buffer
from .secret_create_191_http_transport import FortiPam191SecretCreateHttpTransport
from .secret_create_191_private_adapter import SecretCreate191WebBinding
from .secret_create_m4_runtime import SecretCreateM4ExecutionBinding
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable
from .web_secret_fixture_creation import (WebSecretFixtureCreationEvidence, _ROW,
                                          _qualify_web_creation_execution)
from .web_secret_fixture_creation_reader import read_web_secret_fixture_creation
from .web_secret_create_ack import (WebSecretCreateAckCapture, WebSecretCreateAcknowledgement, _ack_digest)

_HEADER = b"fortipam-private-web-creation-v1\n"
_FILE = "creation.record"
_PENDING = "creation.pending"
_ACK_FILE = "creation.ack"
_ACK_HEADER = b"fortipam-private-web-creation-ack-v1\n"
_LIMIT = 16_384
_ERROR = "The private Web fixture creation record is unavailable."
_FIELDS = frozenset({"native_secret_id", "serial_digest", "baseline_json", "baseline_digest",
                      "execution_digest", "creation_digest"})


class WebSecretFixtureCreationRecordError(ValueError):
    """Categorical refusal without record contents, selectors or private paths."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _directory(path: Path) -> int:
    descriptor: int | None = None
    try:
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError
        return descriptor
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError from None


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretFixtureAcknowledgedCreation:
    """Original ACK matched to sealed metadata/M4; no execution permission."""

    creation: WebSecretFixtureCreationEvidence
    acknowledgement: WebSecretCreateAcknowledgement

    def __repr__(self) -> str:
        return "<WebSecretFixtureAcknowledgedCreation redacted>"

    __str__ = __repr__


class WebSecretFixtureCreationRecord:
    """One startup-bound local record; none of its methods dispatch mutations."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, *,
            transport: FortiPam191SecretCreateHttpTransport, create_binding: SecretCreate191WebBinding,
            execution_binding: SecretCreateM4ExecutionBinding, execution_store: PersistentM4ExecutionStateStore,
            serial_digest: str, expected_store_digest: str, directory: Path, key_file: Path) -> None:
        key = bytearray()
        descriptor: int | None = None
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                    or type(transport) is not FortiPam191SecretCreateHttpTransport
                    or type(create_binding) is not SecretCreate191WebBinding
                    or type(execution_binding) is not SecretCreateM4ExecutionBinding
                    or type(execution_store) is not PersistentM4ExecutionStateStore or config != transport._config
                    or type(serial_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", serial_digest) is None
                    or type(expected_store_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", expected_store_digest) is None):
                raise ValueError
            descriptor = _directory(directory)
            info = os.fstat(descriptor)
            key = _read_private_buffer(key_file, 128)
            if not 32 <= len(key) <= 128 or key_file.stat().st_nlink != 1:
                raise ValueError
            self._key = bytes(key)
            self._directory = directory
            self._directory_id = info.st_dev, info.st_ino
            self._config = config
            self._transport = transport
            self._create_binding = create_binding
            self._execution_binding = execution_binding
            self._execution_store = execution_store
            self._serial = serial_digest
            self._store = expected_store_digest
            self._ack_capture: WebSecretCreateAckCapture | None = transport._web_ack_capture
            if self._ack_capture is not None:
                self._ack_capture.__post_init__()
                if self._ack_capture.serial_digest != serial_digest:
                    raise ValueError
            self._ack_source = (None if self._ack_capture is None else canonical_digest({
                "capture": self._ack_capture.source_digest, "origin": config.base_url,
                "bearer": hashlib.sha256(config.bearer_token.encode()).hexdigest()}))
            # Startup context is independent of any caller-supplied evidence.
            self._namespace = canonical_digest({"directory": str(directory),
                "directory_device": info.st_dev, "directory_inode": info.st_ino, "key_file": str(key_file),
                "key_digest": hashlib.sha256(self._key).hexdigest(), "origin": config.base_url,
                "serial": serial_digest, "store": expected_store_digest,
                "create": hashlib.sha256(_canonical(asdict(create_binding))).hexdigest(),
                "plan": execution_binding.plan.plan_digest, "authorization": execution_binding.authorization.authorization_digest,
                "scope": execution_binding.lease_request.scope_digest,
                "audience": execution_binding.lease_request.audience_digest,
                "policy": execution_binding.lease_request.policy_decision_digest})
        except Exception:
            raise WebSecretFixtureCreationRecordError(_ERROR) from None
        finally:
            _zeroize_mutable(key)
            if descriptor is not None:
                os.close(descriptor)

    def __repr__(self) -> str:
        return "<WebSecretFixtureCreationRecord redacted>"

    __str__ = __repr__

    def _directory_fd(self) -> int:
        descriptor = _directory(self._directory)
        info = os.fstat(descriptor)
        if (info.st_dev, info.st_ino) != self._directory_id:
            os.close(descriptor)
            raise ValueError
        return descriptor

    def _seal(self, payload: memoryview) -> str:
        digest = hmac.new(self._key, _HEADER + self._namespace.encode("ascii") + b"\0", hashlib.sha256)
        digest.update(payload)
        return digest.hexdigest()

    def _check_pending(self, directory: int, identity: tuple[int, int] | None) -> None:
        try:
            info = os.stat(_PENDING, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            if identity is not None:
                raise ValueError from None
            return
        if (identity is None or (info.st_dev, info.st_ino) != identity
                or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size != 0):
            raise ValueError

    def record_creation(self) -> WebSecretFixtureCreationEvidence:
        """Read the original native/M4 context once and write an exclusive record.

        A durable pending marker precedes the read/write and remains on failure.
        Its final removal commits the already synced and validated record. No
        fallible verification or fsync follows that commit. A crash may restore
        the marker, causing conservative refusal and explicit reconciliation;
        neither a pending record nor this method permits POST replay.
        """
        descriptor: int | None = None
        pending: int | None = None
        committed = False
        raw = bytearray()
        try:
            descriptor = self._directory_fd()
            self._check_pending(descriptor, None)
            for name in (_FILE, _ACK_FILE):
                try:
                    os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError
            pending = os.open(_PENDING, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=descriptor)
            info = os.fstat(pending)
            pending_identity = info.st_dev, info.st_ino
            os.fsync(pending)
            os.fsync(descriptor)
            os.close(pending)
            pending = None
            evidence = read_web_secret_fixture_creation(self._config, transport=self._transport,
                create_binding=self._create_binding, execution_binding=self._execution_binding,
                execution_store=self._execution_store, serial_digest=self._serial, expected_store_digest=self._store)
            raw = bytearray(_canonical({"namespace": self._namespace, "evidence": asdict(evidence)}))
            if not 0 < len(raw) <= _LIMIT:
                raise ValueError
            with memoryview(raw) as payload:
                seal = self._seal(payload)
            output = os.open(_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
            with os.fdopen(output, "wb") as stream:
                stream.write(_HEADER + seal.encode("ascii") + b"\n")
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if self._ack_capture is not None:
                observation = self._transport.read_web_create_dispatch_observation(
                    self._create_binding, self._execution_binding.lease_request)
                if (observation is None or type(observation.native_ack) is not WebSecretCreateAcknowledgement
                        or observation.native_ack.native_secret_id != evidence.native_secret_id
                        or observation.native_ack.serial_digest != evidence.serial_digest
                        or self._transport._web_ack_capture != self._ack_capture
                        or self._transport._config != self._config):
                    raise ValueError
                ack_fields = asdict(observation.native_ack)
                if not self._ack_capture.observe_source:
                    if ack_fields.pop("observed_status") is not None:
                        raise ValueError
                ack = bytearray(_canonical({"namespace": self._namespace, "source": self._ack_source,
                    "creation": evidence.creation_digest, "ack": ack_fields}))
                try:
                    with memoryview(ack) as payload:
                        ack_seal = self._ack_seal(payload)
                    output = os.open(_ACK_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=descriptor)
                    with os.fdopen(output, "wb") as stream:
                        stream.write(_ACK_HEADER + ack_seal.encode("ascii") + b"\n")
                        stream.write(ack)
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    _zeroize_mutable(ack)
            os.fsync(descriptor)
            check = self._directory_fd()
            os.close(check)
            # Validate while the durable marker still prevents public adoption.
            verified = self._read_creation(pending_identity)
            if self._ack_capture is not None:
                self._read_ack(verified, pending_identity)
                if self._read_creation(pending_identity) != verified:
                    raise ValueError
            self._check_pending(descriptor, pending_identity)
            check = self._directory_fd()
            os.close(check)
            os.unlink(_PENDING, dir_fd=descriptor)
            committed = True
            return verified
        except Exception:
            raise WebSecretFixtureCreationRecordError(_ERROR) from None
        finally:
            _zeroize_mutable(raw)
            if pending is not None:
                os.close(pending)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    # The commit point is authoritative; a descriptor-close
                    # error cannot turn a committed record into a failed write.
                    if not committed:
                        raise WebSecretFixtureCreationRecordError(_ERROR) from None

    def read_creation(self) -> WebSecretFixtureCreationEvidence:
        """Reload only a sealed record and original M4; never manufacture HTTP ACK."""
        return self._read_creation(None)

    def _ack_seal(self, payload: memoryview) -> str:
        digest = hmac.new(self._key, _ACK_HEADER + self._namespace.encode("ascii") + b"\0", hashlib.sha256)
        digest.update(payload)
        return digest.hexdigest()

    def read_acknowledged_creation(self) -> WebSecretFixtureAcknowledgedCreation:
        """Reload only an original ACK seal and its original metadata/M4 record.

        Missing legacy ACK, new API source, pending writes or changed records
        refuse; no unsigned adoption, raw response reconstruction or I/O retry.
        This supplies private creation provenance, not mutable action authority.
        """
        creation = self.read_creation()
        ack = self._read_ack(creation, None)
        if self.read_creation() != creation:
            raise WebSecretFixtureCreationRecordError(_ERROR)
        return WebSecretFixtureAcknowledgedCreation(creation, ack)

    def _read_ack(self, creation: WebSecretFixtureCreationEvidence,
                  pending_identity: tuple[int, int] | None) -> WebSecretCreateAcknowledgement:
        directory: int | None = None
        descriptor: int | None = None
        raw = bytearray(_LIMIT + len(_ACK_HEADER) + 66)
        try:
            capture = self._ack_capture
            if (type(capture) is not WebSecretCreateAckCapture
                    or self._transport._web_ack_capture != capture or self._transport._config != self._config):
                raise ValueError
            capture.__post_init__()
            source = canonical_digest({"capture": capture.source_digest, "origin": self._config.base_url,
                "bearer": hashlib.sha256(self._config.bearer_token.encode()).hexdigest()})
            if source != self._ack_source or capture.serial_digest != self._serial:
                raise ValueError
            directory = self._directory_fd()
            self._check_pending(directory, pending_identity)
            descriptor = os.open(_ACK_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            initial = os.fstat(descriptor)
            if (not stat.S_ISREG(initial.st_mode) or initial.st_uid != os.getuid() or initial.st_nlink != 1
                    or stat.S_IMODE(initial.st_mode) != 0o600 or not 0 < initial.st_size < len(raw)):
                raise ValueError
            count = os.readv(descriptor, [raw])
            final = os.fstat(descriptor)
            current = os.stat(_ACK_FILE, dir_fd=directory, follow_symlinks=False)
            if (count != initial.st_size or os.read(descriptor, 1)
                    or (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns)
                    != (final.st_size, final.st_mtime_ns, final.st_ctime_ns)
                    or (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino)):
                raise ValueError
            raw = _take_mutable_prefix(raw, count)
            seal_start = len(_ACK_HEADER)
            payload_start = seal_start + 65
            if raw[:seal_start] != _ACK_HEADER or raw[payload_start - 1] != 10:
                raise ValueError
            with memoryview(raw)[payload_start:] as payload:
                expected = self._ack_seal(payload)
            if not hmac.compare_digest(raw[seal_start:payload_start - 1], expected.encode("ascii")):
                raise ValueError
            value = json.loads(raw[payload_start:])
            ack_keys = {"native_secret_id", "serial_digest", "acknowledgement_digest"}
            if capture.observe_source:
                ack_keys.add("observed_status")
            if (type(value) is not dict or set(value) != {"namespace", "source", "creation", "ack"}
                    or value["namespace"] != self._namespace or value["source"] != source
                    or value["creation"] != creation.creation_digest or type(value["ack"]) is not dict
                    or set(value["ack"]) != ack_keys):
                raise ValueError
            fields = value["ack"]
            identifier = fields["native_secret_id"]
            observed_status = fields.get("observed_status")
            if capture.observe_source and (type(observed_status) is not str or observed_status not in {"OK", "success"}):
                raise ValueError
            if (type(identifier) is not int or identifier != creation.native_secret_id
                    or type(fields["serial_digest"]) is not str or fields["serial_digest"] != self._serial
                    or type(fields["acknowledgement_digest"]) is not str
                    or fields["acknowledgement_digest"] != _ack_digest(identifier, capture, observed_status)):
                raise ValueError
            check = self._directory_fd()
            os.close(check)
            self._check_pending(directory, pending_identity)
            return WebSecretCreateAcknowledgement(identifier, self._serial, fields["acknowledgement_digest"], observed_status)
        except Exception:
            raise WebSecretFixtureCreationRecordError(_ERROR) from None
        finally:
            _zeroize_mutable(raw)
            try:
                if descriptor is not None:
                    os.close(descriptor)
            finally:
                if directory is not None:
                    os.close(directory)

    def _read_creation(self, pending_identity: tuple[int, int] | None) -> WebSecretFixtureCreationEvidence:
        directory: int | None = None
        descriptor: int | None = None
        raw = bytearray(_LIMIT + len(_HEADER) + 66)
        try:
            directory = self._directory_fd()
            self._check_pending(directory, pending_identity)
            descriptor = os.open(_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            initial = os.fstat(descriptor)
            if (not stat.S_ISREG(initial.st_mode) or initial.st_uid != os.getuid() or initial.st_nlink != 1
                    or stat.S_IMODE(initial.st_mode) != 0o600 or not 0 < initial.st_size < len(raw)):
                raise ValueError
            count = os.readv(descriptor, [raw])
            final = os.fstat(descriptor)
            current = os.stat(_FILE, dir_fd=directory, follow_symlinks=False)
            if (count != initial.st_size or os.read(descriptor, 1)
                    or (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns)
                    != (final.st_size, final.st_mtime_ns, final.st_ctime_ns)
                    or (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino)):
                raise ValueError
            raw = _take_mutable_prefix(raw, count)
            seal_start = len(_HEADER)
            payload_start = seal_start + 65
            if raw[:seal_start] != _HEADER or raw[payload_start - 1] != 10:
                raise ValueError
            with memoryview(raw)[payload_start:] as payload:
                expected = self._seal(payload)
            # A modified payload is refused before JSON decoding any value.
            if not hmac.compare_digest(raw[seal_start:payload_start - 1], expected.encode("ascii")):
                raise ValueError
            value = json.loads(raw[payload_start:])
            if (type(value) is not dict or set(value) != {"namespace", "evidence"}
                    or value["namespace"] != self._namespace or type(value["evidence"]) is not dict
                    or set(value["evidence"]) != _FIELDS):
                raise ValueError
            fields = value["evidence"]
            if any(type(fields[key]) is not str or re.fullmatch(r"[a-f0-9]{64}", fields[key]) is None
                   for key in _FIELDS - {"native_secret_id", "baseline_json"}):
                raise ValueError
            if (type(fields["native_secret_id"]) is not int or not 0 < fields["native_secret_id"] <= 2**31 - 1
                    or fields["serial_digest"] != self._serial or type(fields["baseline_json"]) is not str):
                raise ValueError
            baseline = fields["baseline_json"].encode("ascii")
            if hashlib.sha256(b"private-web-fixture-baseline/v1\0" + baseline).hexdigest() != fields["baseline_digest"]:
                raise ValueError
            row = json.loads(baseline)
            if (type(row) is not dict or set(row) != _ROW or type(row["id"]) is not int
                    or row["id"] != fields["native_secret_id"] or type(row["folder"]) is not int
                    or not 0 < row["folder"] <= 2**31 - 1 or type(row["uuid"]) is not str
                    or str(uuid.UUID(row["uuid"])) != row["uuid"] or uuid.UUID(row["uuid"]).int == 0):
                raise ValueError
            expected_row = {"name": self._create_binding.secret_name, "template": "Web Account", "target": "",
                        "inherit-permission": "enable", "recording": "enable", "http-service-status": "up",
                        "instruction-profile": ""}
            if any(type(row[key]) is not type(value) or row[key] != value for key, value in expected_row.items()):
                raise ValueError
            execution = _qualify_web_creation_execution(create_binding=self._create_binding,
                execution_binding=self._execution_binding, execution_store=self._execution_store,
                expected_store_digest=self._store)
            if execution != fields["execution_digest"]:
                raise ValueError
            request = self._execution_binding.lease_request
            creation = canonical_digest({"execution": execution, "baseline": fields["baseline_digest"],
                "origin": self._config.base_url, "serial": self._serial, "scope": request.scope_digest,
                "audience": request.audience_digest, "policy": request.policy_decision_digest})
            if creation != fields["creation_digest"] or _canonical(row) != baseline:
                raise ValueError
            check = self._directory_fd()
            os.close(check)
            self._check_pending(directory, pending_identity)
            return WebSecretFixtureCreationEvidence(**cast(dict[str, str | int], fields))  # type: ignore[arg-type]
        except Exception:
            raise WebSecretFixtureCreationRecordError(_ERROR) from None
        finally:
            _zeroize_mutable(raw)
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                os.close(directory)
