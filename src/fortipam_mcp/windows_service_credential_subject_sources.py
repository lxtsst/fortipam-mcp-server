"""Private original service-subject enrollment and guarded central material source.

The fixed native producer must bind the verified MCP requester before creating
its original SID/service and sign this enrollment after original readback.
Trusted composition supplies a no-input fixed metadata inspector and the exact
central registration guard. No Tool accepts these callbacks, paths or records.
Metadata qualification grants no M4/C3 authority; loading additionally requires
the existing original-dispatch and material-acquisition ownership proofs.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from threading import RLock

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import (C3MaterialBinding, MaterialAccessDenied, MaterialBindingStatus,
    MaterialLeaseRequest, MaterialProviderClass, MaterialPurpose, _OpaqueC3Object)
from v4_planning.models import require_digest
from v4_planning.secret_create_adapter import SECRET_CREATE_ACTION_ID, SECRET_CREATE_ACTION_VERSION

from . import secret_bulk_import_metadata as parser
from .local_user_reset_projection import _object_spans
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_central_lab_provider import OwnerOnlyCentralLabSecretCreateEnvFileLoader
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .windows_execution_secret_contract import REQUEST_UUID, WindowsExecutionSecretDefaults, _LOCAL_USER, _machine
from .windows_execution_secret_material import _OriginalDispatch
from .windows_service_credential_contract import WindowsServiceCredentialBinding
from .windows_service_credential_material import ADAPTER_REF, TARGET_REF, windows_service_credential_parameters_digest
from .windows_service_credential_server_identity import WindowsServiceCredentialServerIdentity, WindowsServiceCredentialServerIdentitySnapshot
from .windows_service_credential_target_sources import WindowsServiceCredentialTargetObservation, WindowsServiceCredentialTargetSources

CONTRACT = "fortipam-service-original-subject-mcp-enrollment-v1"
DOMAIN = b"fortipam-service-original-subject-enrollment/v1\x00"
_ERROR = "The original service credential subject source is unavailable."
_DIGESTS = frozenset({"requester_digest", "creator_transport_digest", "target_reference_context_digest",
    "enrollment_context_digest", "subject_sid_digest", "user_state_digest", "service_state_digest",
    "birth_digest", "host_digest", "hardware_digest", "actor_digest", "native_source_digest", "username_mac", "password_mac",
    "retired_marker_digest", "material_claim_path_digest"})
_RECORD_FIELDS = _DIGESTS | {"contract", "machine_name", "user_name", "created_at", "subject_expires_at"}
_INSPECT_DIGESTS = frozenset({"enrollment_context_digest", "subject_sid_digest", "user_state_digest", "service_state_digest",
    "birth_digest", "host_digest", "hardware_digest", "actor_digest"})
_INSPECT_FLAGS = frozenset({"completed", "nonadmin", "service_stopped", "profile_absent", "hive_absent",
    "service_right_only", "target_address_matches", "original_credential_verification_retained"})


def _private_read(path: Path, maximum: int) -> bytearray:
    raw = bytearray()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    def identity(info: os.stat_result) -> tuple[int, ...]:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or not 0 < info.st_size <= maximum):
            raise ValueError
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum+1-len(raw)))
            if not chunk: break
            raw.extend(chunk)
        if len(raw) != info.st_size or identity(os.fstat(descriptor)) != identity(info) or identity(path.lstat()) != identity(info):
            raise ValueError
        return raw
    except BaseException:
        _zeroize_mutable(raw)
        raise
    finally:
        os.close(descriptor)


def _fields(raw: bytearray, expected: frozenset[str]) -> dict[str, tuple[int, int]]:
    start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
    if _skip_json_space(raw, end) != len(raw):
        raise ValueError
    parser._validate_json(raw, start, end, depth=0, budget=[2000])
    fields = _object_spans(raw, start, end)
    if set(fields) != expected:
        raise ValueError
    return fields


def _path_digest(path: Path) -> str:
    return hashlib.sha256(os.fsencode(path.resolve(strict=False))).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceSubjectObservation(_OpaqueC3Object):
    target_reference_context_digest: str
    subject_context_digest: str
    subject_sid_digest: str
    service_context_digest: str
    material_source_context_digest: str
    observed_at: int
    expires_at: int

    def summary(self) -> dict[str, object]:
        return dict(original_nonadmin_subject_metadata_bound=True, protected_reference_available=True,
            verified_mcp_requester_bound=True, credential_values_loaded=False, c3_lease_issued=False,
            current_service_password_consistency_qualified=False, activity_qualified=False,
            execution_authorized=False, runtime_registered=False)


class WindowsServiceCredentialSubjectSources(_OpaqueC3Object):
    """One live metadata admission; a separate M4 binding guards all material use."""
    def __init__(self, identity: WindowsServiceCredentialServerIdentity, *,
            snapshot: WindowsServiceCredentialServerIdentitySnapshot,
            target_source: WindowsServiceCredentialTargetSources, target_observation: WindowsServiceCredentialTargetObservation,
            enrollment_file: Path, enrollment_key_file: Path, retired_marker: Path, material_use_claim_file: Path,
            loader: OwnerOnlyCentralLabSecretCreateEnvFileLoader, inspect_original: Callable[[], bytearray],
            registration_current: Callable[[], bool], enabled: bool = False) -> None:
        self._key = bytearray()
        try:
            if (type(identity) is not WindowsServiceCredentialServerIdentity
                    or type(snapshot) is not WindowsServiceCredentialServerIdentitySnapshot
                    or type(target_source) is not WindowsServiceCredentialTargetSources
                    or type(target_observation) is not WindowsServiceCredentialTargetObservation
                    or type(loader) is not OwnerOnlyCentralLabSecretCreateEnvFileLoader
                    or not callable(inspect_original) or not callable(registration_current) or type(enabled) is not bool):
                raise ValueError
            self._identity, self._snapshot, self._target, self._target_observation = identity, snapshot, target_source, target_observation
            self._file, self._key_file, self._retired = Path(enrollment_file), Path(enrollment_key_file), Path(retired_marker)
            self._claim_file = Path(material_use_claim_file)
            self._path_pins = (self._file, self._key_file, self._retired, self._claim_file)
            if (any(not path.is_absolute() for path in (self._file, self._key_file, self._retired, self._claim_file))
                    or len({self._file, self._key_file, self._retired, self._claim_file}) != 4):
                raise ValueError
            key = _private_read(self._key_file, 32)
            try: self._key.extend(key)
            finally: _zeroize_mutable(key)
            if len(self._key) != 32:
                raise ValueError
            self._loader, self._inspect, self._registration, self._enabled = loader, inspect_original, registration_current, enabled
            self._pins = (identity, snapshot, target_source, target_observation, loader, inspect_original, registration_current)
            self._loader_pins = (loader._secret_env_path, loader._username_variable_name, loader._password_variable_name)
            self._loader_methods = (loader.validate_prebound, loader.load_secret_create_material_once)
            self._closed = self._failed = self._used = self._load_attempted = False
            self._current: WindowsServiceSubjectObservation | None = None
            self._seal: str | None = None
            self._guard: _OriginalDispatch | None = None
            self._last = -1
            self._lock = RLock()
            self._material_binding = C3MaterialBinding()
            self._binding_pin = self._material_binding
            self._record, self._file_digest = self._read_enrollment()
            if (self._record["retired_marker_digest"] != _path_digest(self._retired)
                    or self._record["material_claim_path_digest"] != _path_digest(self._claim_file)):
                raise ValueError
            self._now()
        except Exception:
            _zeroize_mutable(self._key)
            raise MaterialAccessDenied(_ERROR) from None

    @property
    def material_binding(self) -> C3MaterialBinding:
        if self._closed or self._material_binding is not self._binding_pin:
            raise MaterialAccessDenied(_ERROR)
        return self._material_binding

    def _read_enrollment(self) -> tuple[dict[str, object], str]:
        raw = _private_read(self._file, 8192)
        try:
            wrapper = _fields(raw, frozenset({"record", "mac"}))
            signature = parser._scalar(raw, wrapper["mac"])
            if type(signature) is not str:
                raise ValueError
            start, end = wrapper["record"]
            with memoryview(raw)[start:end] as token:
                proof = hmac.new(self._key, DOMAIN, hashlib.sha256); proof.update(token)
                actual = proof.hexdigest()
            if not hmac.compare_digest(signature, actual):
                raise ValueError
            fields = _object_spans(raw, start, end)
            if set(fields) != _RECORD_FIELDS:
                raise ValueError
            record = {key: parser._scalar(raw, span) for key, span in fields.items()}
            if record["contract"] != CONTRACT:
                raise ValueError
            for key in _DIGESTS:
                value = record[key]
                if type(value) is not str: raise ValueError
                require_digest(value, "original_service_subject")
            machine, user = record["machine_name"], record["user_name"]
            if (type(machine) is not str or type(user) is not str
                    or _LOCAL_USER.fullmatch(user.encode("ascii")) is None):
                raise ValueError
            _machine(machine)
            if any(type(record[key]) is not int for key in ("created_at", "subject_expires_at")):
                raise ValueError
            return record, hashlib.sha256(raw).hexdigest()
        finally:
            _zeroize_mutable(raw)

    def _now(self) -> int:
        if (self._closed or self._failed or self._enabled is not True or self._retired.exists() or self._retired.is_symlink()
                or self._path_pins != (self._file, self._key_file, self._retired, self._claim_file)
                or self._record["retired_marker_digest"] != _path_digest(self._retired)
                or self._record["material_claim_path_digest"] != _path_digest(self._claim_file)
                or any(current is not pinned for current, pinned in zip((self._identity, self._snapshot, self._target,
                    self._target_observation, self._loader, self._inspect, self._registration), self._pins, strict=True))
                or self._loader_pins != (self._loader._secret_env_path, self._loader._username_variable_name, self._loader._password_variable_name)
                or self._loader_methods != (self._loader.validate_prebound, self._loader.load_secret_create_material_once)):
            raise ValueError
        self._identity.require_current(self._snapshot, purpose="create")
        original = self._record["requester_digest"]
        if type(original) is not str:
            raise ValueError
        self._identity.require_original_requester(self._snapshot, original_requester_digest=original)
        self._target.check_current(self._target_observation)
        if self._record["target_reference_context_digest"] != self._target_observation.target_reference_context_digest:
            raise ValueError
        key = _private_read(self._key_file, 32)
        try:
            if not hmac.compare_digest(key, self._key) or self._read_enrollment()[1] != self._file_digest:
                raise ValueError
        finally:
            _zeroize_mutable(key)
        now = self._identity._now()
        created, expires = self._record["created_at"], self._record["subject_expires_at"]
        if (type(created) is not int or type(expires) is not int or not 0 <= created <= now < expires
                or now < self._last or self._registration() is not True):
            raise ValueError
        self._last = now
        return now

    def _inspect_current(self) -> None:
        self._now(); raw = self._inspect()
        try:
            if type(raw) is not bytearray or not 0 < len(raw) <= 8192:
                raise ValueError
            fields = _fields(raw, _INSPECT_DIGESTS | _INSPECT_FLAGS)
            for key in _INSPECT_FLAGS:
                if parser._scalar(raw, fields[key]) is not True:
                    raise ValueError
            for key in _INSPECT_DIGESTS:
                value = parser._scalar(raw, fields[key])
                if type(value) is not str or value != self._record[key]:
                    raise ValueError
            self._now()
        finally:
            if isinstance(raw, bytearray): _zeroize_mutable(raw)

    def qualify_once(self) -> WindowsServiceSubjectObservation:
        try:
            with self._lock:
                if self._used or self._claim_file.exists() or self._claim_file.is_symlink():
                    raise ValueError
                self._used = True; now = self._now()
                self._inspect_current()
                if self._loader.validate_prebound() is not MaterialBindingStatus.AVAILABLE:
                    raise ValueError
                self._now()
                subject = canonical_digest({key: self._record[key] for key in ("enrollment_context_digest",
                    "subject_sid_digest", "user_state_digest", "birth_digest", "hardware_digest", "host_digest", "actor_digest")})
                service = canonical_digest({key: self._record[key] for key in ("enrollment_context_digest", "service_state_digest", "birth_digest")})
                material = canonical_digest(dict(contract=CONTRACT, enrollment=self._file_digest,
                    current_mcp=self._snapshot.context_digest, subject=subject, service=service))
                expires = self._record["subject_expires_at"]
                if type(expires) is not int:
                    raise ValueError
                self._current = WindowsServiceSubjectObservation(self._target_observation.target_reference_context_digest,
                    subject, str(self._record["subject_sid_digest"]), service, material, now, min(now+30, self._snapshot.expires_at, expires))
                self._seal = hmac.new(self._key, canonical_digest(asdict(self._current)).encode(), hashlib.sha256).hexdigest()
                return self._current
        except Exception:
            self._failed = True
            raise MaterialAccessDenied(_ERROR) from None

    def check_current(self, observed: WindowsServiceSubjectObservation) -> None:
        try:
            if (type(observed) is not WindowsServiceSubjectObservation or observed is not self._current
                    or self._now() >= observed.expires_at or self._seal is None
                    or not hmac.compare_digest(hmac.new(self._key, canonical_digest(asdict(observed)).encode(), hashlib.sha256).hexdigest(), self._seal)):
                raise ValueError
        except Exception:
            self._failed = True
            raise MaterialAccessDenied(_ERROR) from None

    def validate_prebound(self) -> MaterialBindingStatus:
        try:
            if self._current is None or self._load_attempted or self._claim_file.exists() or self._claim_file.is_symlink():
                raise ValueError
            self.check_current(self._current)
            return self._loader.validate_prebound()
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE

    def bind_original_dispatch(self, *, profile: WindowsServiceCredentialBinding, defaults: WindowsExecutionSecretDefaults,
            plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, request: MaterialLeaseRequest,
            execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
            material_binding: C3MaterialBinding) -> None:
        """Bind existing M4 proofs only; this never issues a plan or authorization."""
        try:
            with self._lock:
                if (self._guard is not None or self._current is None or material_binding is not self.material_binding
                        or type(profile) is not WindowsServiceCredentialBinding or type(plan) is not M4ExecutionPlan
                        or type(authorization) is not M4ExecutionAuthorization or type(request) is not MaterialLeaseRequest
                        or type(execution_store) is not PersistentM4ExecutionStateStore
                        or type(material_store) is not PersistentMaterialUseStateStore):
                    raise ValueError
                self.check_current(self._current)
                plan.__post_init__(); authorization.__post_init__(); request.__post_init__(); profile.__post_init__()
                if (profile.subject_context_digest != self._current.subject_context_digest
                        or profile.subject_sid_digest != self._current.subject_sid_digest
                        or profile.service_context_digest != self._current.service_context_digest
                        or profile.material_source_context_digest != self._current.material_source_context_digest
                        or profile.target_reference_context_digest != self._current.target_reference_context_digest
                        or profile.machine_name != self._record["machine_name"]
                        or profile.target_name != self._target._name or profile.target_address != self._target._address
                        or profile.serial_digest != self._target._serial
                        or plan.action_id != SECRET_CREATE_ACTION_ID or plan.action_version != SECRET_CREATE_ACTION_VERSION
                        or plan.adapter_ref != ADAPTER_REF or plan.target_ref != TARGET_REF
                        or plan.requester_digest != self._snapshot.requester_digest
                        or authorization.requester_digest != plan.requester_digest
                        or authorization.plan_digest != plan.plan_digest or authorization.plan_ref != plan.plan_ref
                        or authorization.confirmation_digest != plan.confirmation_digest or authorization.approval_digest != plan.approval_digest
                        or plan.compensation_ref is not None
                        or plan.parameters_digest != windows_service_credential_parameters_digest(profile, defaults, create_uuid=REQUEST_UUID)
                        or request.plan_digest != plan.plan_digest or request.authorization_digest != authorization.authorization_digest
                        or request.provider_class is not MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
                        or request.purpose is not MaterialPurpose.INITIAL_ONBOARDING
                        or request.requested_at < authorization.issued_at
                        or request.expires_at > min(authorization.expires_at, plan.expires_at, self._snapshot.expires_at)
                        or not execution_store.monotonic_checkpoint_protocol_bound or not material_store.monotonic_checkpoint_protocol_bound
                        or execution_store._path == material_store._path or execution_store._key_path == material_store._key_path
                        or material_store.uses_key_material(execution_store._key)):
                    raise ValueError
                self._guard = _OriginalDispatch(plan, authorization, execution_store, material_store, request, self._identity._clock)
        except Exception:
            raise MaterialAccessDenied(_ERROR) from None

    def load_secret_create_material_once(self) -> tuple[bytearray, bytearray]:
        loaded: tuple[bytearray, bytearray] | None = None
        transferred = False
        try:
            with self._lock:
                if self._guard is None or self._load_attempted or self._current is None:
                    raise ValueError
                self._guard.require(claimed=True, acquired=True)
                self.check_current(self._current); self._load_attempted = True
                marker = dict(contract=CONTRACT, enrollment=self._file_digest, plan=self._guard.plan.plan_digest,
                    authorization=self._guard.authorization.authorization_digest,
                    material_source=self._current.material_source_context_digest,
                    requester=self._snapshot.requester_digest)
                descriptor = os.open(self._claim_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "w") as stream:
                    json.dump(marker, stream, sort_keys=True, separators=(",", ":")); stream.flush(); os.fsync(stream.fileno())
                directory = os.open(self._claim_file.parent, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(directory)
                finally: os.close(directory)
            self._inspect_current()
            loaded = self._loader.load_secret_create_material_once()
            for index, field in ((0, "username_mac"), (1, "password_mac")):
                if not hmac.compare_digest(hmac.new(self._key, loaded[index], hashlib.sha256).hexdigest(), str(self._record[field])):
                    raise ValueError
            if (loaded[0] is loaded[1] or _LOCAL_USER.fullmatch(loaded[0]) is None
                    or loaded[0] != str(self._record["user_name"]).encode("ascii")):
                raise ValueError
            self._inspect_current()
            self._guard.require(claimed=True, acquired=True); self.check_current(self._current)
            transferred = True
            return loaded
        except Exception:
            raise MaterialAccessDenied(_ERROR) from None
        finally:
            if loaded is not None and not transferred:
                for value in loaded: _zeroize_mutable(value)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current = None; self._seal = None; self._guard = None
            self._record.clear()
            _zeroize_mutable(self._key)
