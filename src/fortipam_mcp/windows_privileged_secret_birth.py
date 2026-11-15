"""Private original ACK/frame/birth custody for two closed reference profiles.

Only an original active M4/C3 dispatch may create write-once send/ACK/birth
records. Two supplied complete rows and independent Password/empty-TOTP brackets
must match the original material. No reader, HTTP writer, authorization issuer,
source qualification, recovery authority or runtime registration is supplied.
The first complete frame seals before material reads. Missing original material
seals and UNKNOWN outcomes are never backfilled by a later current-state proof.
Public privileged and service entries keep distinct exact types and key domains.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
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
from .windows_privileged_secret_contract import (
    WindowsPrivilegedSecretBinding, WindowsPrivilegedSecretMetadata,
    _metadata, _project_windows_privileged_secret_metadata,
)
from .windows_privileged_secret_material import (
    _ReferenceBinding, _reference_profile_refs, _reference_parameters_digest,
)
from .windows_execution_secret_contract import REQUEST_UUID, WindowsExecutionSecretDefaults
from .windows_execution_secret_material import _OriginalDispatch
from .windows_service_credential_contract import (
    WindowsServiceCredentialBinding, WindowsServiceCredentialMetadata, _metadata as _service_metadata,
    _project_windows_service_credential_metadata,
)
from .secret_approval_build29_native_preservation import _qualify_bracket
from .secret_approval_build29_totp_boundary import SecretApprovalBuild29TotpWitness
from .secret_instruction_build29_api_preservation import (
    SecretInstructionBuild29CredentialWitness, _credential_bracket,
)

_ERROR = "The private original Windows privileged Secret birth custody is unavailable."
_DOMAIN = b"windows-privileged-secret-create-custody/v1\x00"
_MATERIAL_KEY_DOMAIN = b"windows-privileged-secret-material-witness/v1\x00"
_USERNAME_DOMAIN = b"windows-privileged-secret-username-token/v1\x00"
_SEND, _ACK, _FRAME, _BIRTH = "create.send.json", "create.ack.json", "create.original-frame.json", "create.full-birth.json"
_SEND_FIELDS = frozenset({"context_digest", "body_digest", "username_digest", "password_digest", "sent_at"})
_ACK_FIELDS = frozenset({"context_digest", "send_digest", "native_secret_id", "ack_digest", "acknowledged_at"})
_FRAME_FIELDS = frozenset({"context_digest", "ack_record_digest", "native_secret_id", "native_uuid",
    "password_field_id", "framing_digest", "raw_frame_digest", "row_fields_digest", "observed_at"})
_BIRTH_FIELDS = frozenset({"context_digest", "ack_record_digest", "native_secret_id", "native_uuid",
                            "state_digest", "password_field_id", "observed_at"})


def _birth_domains(profile: _ReferenceBinding) -> tuple[bytes, bytes, bytes]:
    if type(profile) is WindowsPrivilegedSecretBinding:
        return _DOMAIN, _MATERIAL_KEY_DOMAIN, _USERNAME_DOMAIN
    if type(profile) is WindowsServiceCredentialBinding:
        return (b"windows-service-credential-create-custody/v1\x00",
                b"windows-service-credential-material-witness/v1\x00",
                b"windows-service-credential-username-token/v1\x00")
    raise ValueError


class WindowsPrivilegedSecretBirthError(RuntimeError):
    """A categorical refusal without raw values, selectors or source content."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsPrivilegedSecretOriginalCreation(_OpaqueC3Object):
    """Private original seals, not source admission or deletion authority."""

    native_secret_id: int
    native_uuid: str | None
    state_digest: str | None
    custody_digest: str
    original_outcome: str
    original_verification: str


@dataclass(frozen=True, slots=True, repr=False)
class WindowsReferenceSecretOriginalFrame(_OpaqueC3Object):
    """Original supplied full row only; material/source/recovery remain unproved."""
    native_uuid: str
    password_field_id: int
    framing_digest: str
    original: WindowsPrivilegedSecretOriginalCreation


@dataclass(frozen=True, slots=True, repr=False)
class WindowsReferenceSecretPristineState(_OpaqueC3Object):
    """Supplied current proof, never a replacement for an original material seal."""
    original: WindowsPrivilegedSecretOriginalCreation
    current_state_digest: str
    original_material_seal_present: bool


def _row_field_set_digest(fields: Iterable[str]) -> str:
    """Pin all 1..512 names without widening the C0-C2 canonical limits.

    Preserve every existing small-set digest. Larger native sets could not
    previously be sealed; hash bounded canonical chunks in a separate domain.
    """
    ordered = sorted(fields)
    if not 1 <= len(ordered) <= 512 or len(set(ordered)) != len(ordered):
        raise ValueError
    if len(ordered) <= 64:
        return canonical_digest(ordered)
    return canonical_digest({"contract": "fortipam-reference-secret-large-field-set-v1",
        "field_count": len(ordered), "chunks": [canonical_digest(ordered[start:start + 64])
            for start in range(0, len(ordered), 64)]})


class _ReferenceSecretBirthCustody(_OpaqueC3Object):
    """Require the qualified schema minimum; pin every first-row extra field.

    The private producer must qualify the complete native schema and unprojected
    route. A supplied field set alone attests neither. Runtime decorations absent
    from schema/defaults are admitted only in the original first frame; all
    later rows must retain that exact observed set and every opaque token.
    """
    def __init__(self, directory: Path, witness_key_file: Path, *,
            config: SecretMetadataHttpTransportConfig, profile: _ReferenceBinding,
            defaults: WindowsExecutionSecretDefaults, full_row_fields: frozenset[str], plan: M4ExecutionPlan,
            authorization: M4ExecutionAuthorization, request: MaterialLeaseRequest,
            execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
            clock: Callable[[], int]) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(profile) not in (WindowsPrivilegedSecretBinding, WindowsServiceCredentialBinding)
                    or type(defaults) is not WindowsExecutionSecretDefaults or type(plan) is not M4ExecutionPlan
                    or type(authorization) is not M4ExecutionAuthorization or type(request) is not MaterialLeaseRequest
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or type(material_store) is not PersistentMaterialUseStateStore or not callable(clock)
                    or not execution_store.monotonic_checkpoint_protocol_bound
                    or not material_store.monotonic_checkpoint_protocol_bound):
                raise ValueError
            self._profile = profile
            self._contract, self._adapter_ref, self._target_ref = _reference_profile_refs(profile)
            self._domain, self._material_key_domain, self._username_domain = _birth_domains(profile)
            self._directory, self._key_file = Path(directory), Path(witness_key_file)
            _private_directory(self._directory)
            info = self._directory.stat()
            self._directory_identity = info.st_dev, info.st_ino
            self._key = bytearray(_key(self._key_file))
            if (len({self._key_file, execution_store._path, execution_store._key_path,
                     material_store._path, material_store._key_path}) != 5
                    or self._key_file in {self._directory / name for name in (_SEND, _ACK, _FRAME, _BIRTH)}
                    or hmac.compare_digest(self._key, execution_store._key)
                    or material_store.uses_key_material(bytes(self._key))
                    or material_store.uses_key_material(execution_store._key)):
                raise ValueError
            if (type(full_row_fields) is not frozenset or not 1 <= len(full_row_fields) <= 512
                    or any(type(name) is not str or not name or len(name.encode()) > 128
                           or any(ord(c) < 32 for c in name) for name in full_row_fields)
                    or not (set(self._proposed_metadata()) | {"field", "subscriber", "target-info",
                            "totp-setting", "instruction-profile"}) <= full_row_fields):
                raise ValueError
            self._row_fields = full_row_fields
            self._row_fields_digest = _row_field_set_digest(full_row_fields)
            self._config, self._profile, self._defaults = config, profile, defaults
            self._plan, self._authorization, self._request = plan, authorization, request
            self._execution_store, self._material_store = execution_store, material_store
            self._guard = _OriginalDispatch(plan, authorization, execution_store, material_store, request, clock)
            self._source = self._source_digest()
            self._context = self._context_digest()
            self._begin_consumed = self._send_started = self._ack_consumed = self._birth_consumed = self._closed = False
            self._frame_consumed = False
            self._lock = RLock()
            self._validate()
        except Exception:
            if hasattr(self, "_key"):
                _zeroize_mutable(self._key)
            raise WindowsPrivilegedSecretBirthError(_ERROR) from None

    def _proposed_metadata(self) -> dict[str, object]:
        if type(self._profile) is WindowsPrivilegedSecretBinding:
            return _metadata(self._profile)
        if type(self._profile) is WindowsServiceCredentialBinding:
            return _service_metadata(self._profile)
        raise ValueError

    def close(self) -> None:
        """Erase this instance's key; retain original files for independent reads."""
        with self._lock:
            self._closed = True
            _zeroize_mutable(self._key)

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
        return canonical_digest({"contract": self._contract, "parameters": self._plan.parameters_digest,
            "row_fields": _row_field_set_digest(self._row_fields),
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
        if (_reference_profile_refs(self._profile) != (self._contract, self._adapter_ref, self._target_ref)
                or _birth_domains(self._profile) != (self._domain, self._material_key_domain, self._username_domain)
                or p.action_id != "secret-create-from-reference" or p.action_version != "1.0.0"
                or p.adapter_ref != self._adapter_ref or p.target_ref != self._target_ref or p.compensation_ref is not None
                or p.parameters_digest != _reference_parameters_digest(self._profile, self._defaults,
                    create_uuid=REQUEST_UUID)
                or r.action_id != p.action_id or r.action_version != p.action_version
                or r.provider_class is not MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
                or r.purpose is not MaterialPurpose.INITIAL_ONBOARDING or r.expires_at - r.requested_at > 60
                or r.plan_digest != p.plan_digest or r.authorization_digest != a.authorization_digest
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest
                or a.requester_digest != p.requester_digest or a.confirmation_digest != p.confirmation_digest
                or a.approval_digest != p.approval_digest or r.requested_at < a.issued_at
                or r.expires_at > min(a.expires_at, p.expires_at)
                or type(self._row_fields) is not frozenset
                or _row_field_set_digest(self._row_fields) != self._row_fields_digest
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
        return hmac.new(self._key, self._domain + name.encode() + b"\x00" + raw, hashlib.sha256).hexdigest()

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
                elif key in ("native_secret_id", "password_field_id"):
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
        return hmac.new(self._key, self._material_key_domain + self._context.encode("ascii"), hashlib.sha256).digest()

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
        wanted = self._proposed_metadata()
        if set(fields) != set(wanted) | {"field"}:
            raise ValueError
        for key, expected in wanted.items():
            if type(expected) is list:
                if parser._array(raw, fields[key], 0):
                    raise ValueError
            else:
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
            token = hmac.new(material_key, _MATERIAL_DOMAIN if name == "Password" else self._username_domain, hashlib.sha256)
            with memoryview(raw)[slice(*entry["value"])] as value:
                token.update(value)
            witnesses[name.lower() + "_digest"] = token.hexdigest()
        witness = hmac.new(self._key, self._domain + b"request-body\x00", hashlib.sha256)
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
                if any(os.path.lexists(self._directory / name) for name in (_SEND, _ACK, _FRAME, _BIRTH)):
                    raise ValueError
                witnesses = self._body_witnesses(body)
                self._writing_now()
                self._write(_SEND, {"context_digest": self._context, **witnesses, "sent_at": now})
                self._send_started = True
        except Exception:
            self._closed = True
            raise WindowsPrivilegedSecretBirthError(_ERROR) from None
        except BaseException:
            self._closed = True
            raise

    def capture_original_ack(self, raw: bytearray, *, http_status: int, content_type: str) -> None:
        try:
            with self._lock:
                now = self._writing_now()
                if (not self._send_started or self._ack_consumed or type(http_status) is not int or http_status != 200
                        or type(content_type) is not str or content_type.split(";", 1)[0].strip().lower() != "application/json"):
                    raise ValueError
                self._ack_consumed = True
                sent = self._record(_SEND, _SEND_FIELDS)
                if type(raw) is not bytearray or not 0 < len(raw) <= 1048576:
                    raise ValueError
                response = hmac.new(self._key, self._domain + b"native-response\x00", hashlib.sha256)
                with memoryview(raw) as response_view:
                    response.update(response_view)
                response_digest = response.hexdigest()
                native_id, status = _consume_database_create_ack_metadata(raw,
                    serial_digest=self._profile.serial_digest, accepted_statuses=frozenset({"success"}))
                self._writing_now()
                ack_digest = hmac.new(self._key, self._domain + b"native-ack\x00" +
                    canonical_digest({"context": self._context, "send": canonical_digest(sent),
                        "native_id": native_id, "status": status, "response": response_digest}).encode(), hashlib.sha256).hexdigest()
                self._write(_ACK, {"context_digest": self._context, "send_digest": canonical_digest(sent),
                    "native_secret_id": native_id, "ack_digest": ack_digest, "acknowledged_at": now})
        except Exception:
            self._closed = True
            raise WindowsPrivilegedSecretBirthError(_ERROR) from None
        except BaseException:
            self._closed = True
            raise
        finally:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)

    def _full_frame(self, raw: bytearray, native_id: int, key: bytes | bytearray,
            expected_uuid: str | None = None) -> tuple[str, int, str]:
        observed: WindowsPrivilegedSecretMetadata | WindowsServiceCredentialMetadata
        if type(self._profile) is WindowsPrivilegedSecretBinding:
            observed = _project_windows_privileged_secret_metadata(raw, self._profile,
                expected_secret_id=native_id, expected_native_uuid=expected_uuid)
        elif type(self._profile) is WindowsServiceCredentialBinding:
            observed = _project_windows_service_credential_metadata(raw, self._profile,
                expected_secret_id=native_id, expected_native_uuid=expected_uuid)
        else:
            raise ValueError
        left = _skip_json_space(raw, 0)
        envelope = _object_spans(raw, left, _json_value_end(raw, left))
        left, right = envelope["results"]
        if raw[left] == 91:
            left, right = parser._array(raw, (left, right), 1)[0]
        row = _object_spans(raw, left, right)
        if not self._row_fields <= row.keys() or parser._scalar(raw, row["instruction-profile"]) != "":
            raise ValueError
        if os.path.lexists(self._directory / _FRAME):
            original_fields = self._record(_FRAME, _FRAME_FIELDS)["row_fields_digest"]
            if _row_field_set_digest(row) != original_fields:
                raise ValueError
        username_span = None
        for span in parser._array(raw, row["field"], 3):
            fields = _object_spans(raw, *span)
            if parser._scalar(raw, fields["name"]) == "Username":
                username_span = fields["value"]
        if username_span is None:
            raise ValueError
        sent = self._record(_SEND, _SEND_FIELDS)
        username = hmac.new(key, self._username_domain, hashlib.sha256)
        with memoryview(raw)[slice(*username_span)] as value:
            username.update(value)
        if not hmac.compare_digest(username.hexdigest(), cast(str, sent["username_digest"])):
            raise ValueError
        totp = _object_spans(raw, *row["totp-setting"])
        if parser._scalar(raw, totp["status"]) != "disable":
            raise ValueError
        first, last = totp["shared-key"]
        if raw[first] != 34 and raw[first:last] != b"null":
            raise ValueError
        # All known/unknown row tokens stay significant except this direct
        # volatile render, qualified by independent explicit-empty witnesses.
        digest = hmac.new(key, self._domain + b"full-row\x00", hashlib.sha256)
        with memoryview(raw)[left:first] as prefix:
            digest.update(prefix)
        digest.update(b'"independently-qualified-empty-totp"')
        with memoryview(raw)[last:right] as suffix:
            digest.update(suffix)
        return observed.native_uuid, observed.password_field_id, digest.hexdigest()

    def capture_original_frame(self, raw: bytearray) -> WindowsReferenceSecretOriginalFrame:
        """Seal the first supplied complete row before independent material reads.

        This preserves original UUID/full-row evidence even when a later material
        request fails. It is not a complete material seal or recovery authority.
        No later instance or terminal creator can add this original record.
        """
        key = bytearray()
        try:
            with self._lock:
                if self._frame_consumed:
                    raise ValueError
                self._frame_consumed = True
                now = self._writing_now()
                if not self._send_started or not self._ack_consumed or self._birth_consumed:
                    raise ValueError
                ack = self._record(_ACK, _ACK_FIELDS)
                key.extend(self._material_key())
                native_id = cast(int, ack["native_secret_id"])
                native_uuid, field_id, framing = self._full_frame(raw, native_id, key)
                start = _skip_json_space(raw, 0)
                envelope = _object_spans(raw, start, _json_value_end(raw, start))
                left, right = envelope["results"]
                if raw[left] == 91:
                    left, right = parser._array(raw, (left, right), 1)[0]
                row_fields_digest = _row_field_set_digest(_object_spans(raw, left, right))
                digest = hmac.new(key, self._domain + b"original-unprojected-row\x00", hashlib.sha256)
                with memoryview(raw)[left:right] as row:
                    digest.update(row)
                self._writing_now()
                self._write(_FRAME, {"context_digest": self._context, "ack_record_digest": canonical_digest(ack),
                    "native_secret_id": native_id, "native_uuid": native_uuid, "password_field_id": field_id,
                    "framing_digest": framing, "raw_frame_digest": digest.hexdigest(),
                    "row_fields_digest": row_fields_digest, "observed_at": now})
                return WindowsReferenceSecretOriginalFrame(native_uuid, field_id, framing, self.inspect_original_creation())
        except Exception:
            self._closed = True
            raise WindowsPrivilegedSecretBirthError(_ERROR) from None
        except BaseException:
            self._closed = True
            raise
        finally:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)
            _zeroize_mutable(key)

    def capture_original_birth(self, before: bytearray, after: bytearray, *,
            password_before: SecretInstructionBuild29CredentialWitness,
            password_after: SecretInstructionBuild29CredentialWitness,
            totp_before: SecretApprovalBuild29TotpWitness,
            totp_after: SecretApprovalBuild29TotpWitness) -> WindowsPrivilegedSecretOriginalCreation:
        """Seal original complete state once, inside the original dispatch only.

        Supplied witness types and field declarations are not provenance proof.
        The fixed trusted producer must qualify complete native rows and the
        same actor/device/subject/key/freshness Password/TOTP source brackets.
        """
        try:
            with self._lock:
                if self._birth_consumed:
                    raise ValueError
                self._birth_consumed = True
                now = self._writing_now()
                if not self._send_started or not self._ack_consumed or not self._frame_consumed or before is after:
                    raise ValueError
                ack = self._record(_ACK, _ACK_FIELDS)
                native_id = cast(int, ack["native_secret_id"])
                uuid_before, field_id, state = self._complete_state(before, after, native_id,
                    password_before=password_before, password_after=password_after,
                    totp_before=totp_before, totp_after=totp_after)
                self._writing_now()
                self._write(_BIRTH, {"context_digest": self._context,
                    "ack_record_digest": canonical_digest(ack), "native_secret_id": native_id,
                    "native_uuid": uuid_before, "state_digest": state,
                    "password_field_id": field_id, "observed_at": now})
                return self.inspect_original_creation()
        except Exception:
            self._closed = True
            raise WindowsPrivilegedSecretBirthError(_ERROR) from None
        except BaseException:
            self._closed = True
            raise
        finally:
            for raw in (before, after):
                if type(raw) is bytearray:
                    _zeroize_mutable(raw)

    def _complete_state(self, before: bytearray, after: bytearray, native_id: int, *,
            password_before: SecretInstructionBuild29CredentialWitness,
            password_after: SecretInstructionBuild29CredentialWitness,
            totp_before: SecretApprovalBuild29TotpWitness,
            totp_after: SecretApprovalBuild29TotpWitness,
            expected_uuid: str | None = None) -> tuple[str, int, str]:
        if before is after:
            raise ValueError
        frame = self._record(_FRAME, _FRAME_FIELDS)
        native_uuid = cast(str, frame["native_uuid"])
        if frame["native_secret_id"] != native_id or expected_uuid is not None and expected_uuid != native_uuid:
            raise ValueError
        key = self._material_key()
        uuid_before, field_id, frame_before = self._full_frame(before, native_id, key, native_uuid)
        uuid_after, field_after, frame_after = self._full_frame(after, native_id, key, uuid_before)
        if (field_after != field_id or field_id != frame["password_field_id"] or uuid_after != uuid_before
                or not hmac.compare_digest(frame_before, cast(str, frame["framing_digest"]))
                or not hmac.compare_digest(frame_before, frame_after)):
            raise ValueError
        _credential_bracket(password_before, password_after,
            secret_id=native_id, field_id=field_id, key=key)
        sent = self._record(_SEND, _SEND_FIELDS)
        if not hmac.compare_digest(password_before.material_digest, cast(str, sent["password_digest"])):
            raise ValueError
        _qualify_bracket(totp_before, totp_after, key)
        if totp_before.explicit_empty is not True:
            raise ValueError
        state = hmac.new(key, self._domain + b"complete-birth\x00" +
            frame_before.encode() + password_before.material_digest.encode() +
            totp_before.material_digest.encode(), hashlib.sha256).hexdigest()
        return uuid_before, field_id, state

    def consume_pristine_birth(self, before: bytearray, after: bytearray, *,
            password_before: SecretInstructionBuild29CredentialWitness,
            password_after: SecretInstructionBuild29CredentialWitness,
            totp_before: SecretApprovalBuild29TotpWitness,
            totp_after: SecretApprovalBuild29TotpWitness) -> WindowsPrivilegedSecretOriginalCreation:
        """Compare supplied current full state to original seals after dispatch.

        This read-only check may use an independent custody instance after the
        original lease expires. It never writes or repairs seals, changes the
        original outcome, qualifies a source, or authorizes recovery/deletion.
        """
        try:
            with self._lock:
                original = self.inspect_original_creation()
                if (original.original_outcome == "in_progress" or original.native_uuid is None
                        or original.state_digest is None):
                    raise ValueError
                current = self.consume_original_frame_state(before, after,
                    password_before=password_before, password_after=password_after,
                    totp_before=totp_before, totp_after=totp_after)
                if current.original != original or not current.original_material_seal_present:
                    raise ValueError
                return original
        except Exception:
            raise WindowsPrivilegedSecretBirthError(_ERROR) from None
        finally:
            for raw in (before, after):
                if type(raw) is bytearray:
                    _zeroize_mutable(raw)

    def consume_original_frame_state(self, before: bytearray, after: bytearray, *,
            password_before: SecretInstructionBuild29CredentialWitness,
            password_after: SecretInstructionBuild29CredentialWitness,
            totp_before: SecretApprovalBuild29TotpWitness,
            totp_after: SecretApprovalBuild29TotpWitness) -> WindowsReferenceSecretPristineState:
        """Compare current evidence to the original frame and sent material.

        A terminal creator with an original frame but no material seal may be
        observed without changing that absence or its original outcome. This
        evidence alone grants no cleanup permission, source or recovery authority.
        """
        try:
            with self._lock:
                original = self.inspect_original_creation()
                if original.original_outcome == "in_progress" or original.native_uuid is None:
                    raise ValueError
                _, _, state = self._complete_state(before, after,
                    original.native_secret_id, password_before=password_before, password_after=password_after,
                    totp_before=totp_before, totp_after=totp_after, expected_uuid=original.native_uuid)
                if (original.state_digest is not None and not hmac.compare_digest(state, original.state_digest)
                        or self.inspect_original_creation() != original):
                    raise ValueError
                return WindowsReferenceSecretPristineState(original, state, original.state_digest is not None)
        except Exception:
            raise WindowsPrivilegedSecretBirthError(_ERROR) from None
        finally:
            for raw in (before, after):
                if type(raw) is bytearray:
                    _zeroize_mutable(raw)

    def inspect_original_creation(self) -> WindowsPrivilegedSecretOriginalCreation:
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
                frame = self._record(_FRAME, _FRAME_FIELDS) if os.path.lexists(self._directory / _FRAME) else None
                if frame is not None and (frame["ack_record_digest"] != canonical_digest(ack)
                        or frame["native_secret_id"] != ack["native_secret_id"]
                        or cast(int, frame["observed_at"]) < cast(int, ack["acknowledged_at"])):
                    raise ValueError
                meta = self._record(_BIRTH, _BIRTH_FIELDS) if os.path.lexists(self._directory / _BIRTH) else None
                if meta is None and claim.result is not None and str(claim.result.outcome) == "succeeded":
                    raise ValueError
                if meta is not None and (frame is None or meta["ack_record_digest"] != canonical_digest(ack)
                        or meta["native_secret_id"] != ack["native_secret_id"]
                        or meta["native_uuid"] != frame["native_uuid"]
                        or meta["password_field_id"] != frame["password_field_id"]
                        or cast(int, meta["observed_at"]) < cast(int, frame["observed_at"])):
                    raise ValueError
                return WindowsPrivilegedSecretOriginalCreation(cast(int, ack["native_secret_id"]),
                    cast(str, frame["native_uuid"]) if frame else None, cast(str, meta["state_digest"]) if meta else None,
                    canonical_digest({"send": sent, "ack": ack, "original_frame": frame, "full_birth": meta}),
                    str(claim.result.outcome) if claim.result is not None else "in_progress",
                    str(claim.result.verification) if claim.result is not None else "unknown")
        except Exception:
            raise WindowsPrivilegedSecretBirthError(_ERROR) from None


class WindowsPrivilegedSecretBirthCustody(_ReferenceSecretBirthCustody):
    """Exact privileged-profile entry; no caller privilege or profile switch."""
    def __init__(self, directory: Path, witness_key_file: Path, *,
            config: SecretMetadataHttpTransportConfig, profile: WindowsPrivilegedSecretBinding,
            defaults: WindowsExecutionSecretDefaults, full_row_fields: frozenset[str], plan: M4ExecutionPlan,
            authorization: M4ExecutionAuthorization, request: MaterialLeaseRequest,
            execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
            clock: Callable[[], int]) -> None:
        if type(profile) is not WindowsPrivilegedSecretBinding:
            raise WindowsPrivilegedSecretBirthError(_ERROR)
        super().__init__(directory, witness_key_file, config=config, profile=profile, defaults=defaults,
            full_row_fields=full_row_fields, plan=plan, authorization=authorization, request=request,
            execution_store=execution_store, material_store=material_store, clock=clock)
