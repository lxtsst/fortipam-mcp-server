"""Private build29 Windows execution credential prerequisites, never authority.

No network, Tool, runtime registration or existing Secret repair is provided.
The eventual producer must join owned Target/Folder state, M4/C3 authorization,
original native ACK custody, full fixed readback and separate recovery before
using this body. Material remains in private mutable buffers throughout.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from threading import Lock
from types import MappingProxyType
from typing import cast
import uuid

from v4_planning import canonical_digest
from v4_planning.material_provider import MaterialBindingStatus, _OpaqueC3Object
from v4_planning.models import require_digest

from .secret_create_central_lab_provider import CentralLabSecretCreateResolverLoader
from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _append_material, _valid_material_view
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

CONTRACT = "fortipam-700-build29-windows-execution-secret-private-v1"
REQUEST_UUID = "00000000-0000-0000-0000-000000000000"
_ERROR = "The private Windows execution Secret is unavailable."
_MACHINE = re.compile(r"[A-Z0-9][A-Z0-9-]{0,14}\Z")
_LOCAL_USER = re.compile(rb"[A-Za-z0-9][A-Za-z0-9_.-]{0,19}\Z")
_GUARDS: Mapping[str, str | int] = MappingProxyType({
    "target-privilege-account": "disable", "associated-secret": 0, "auto-association": "disable",
    "proxy": "disable", "recording": "disable", "checkout": "disable",
    "checkout-script": "", "checkin-script": "", "checkin-pwd-change": "disable",
    "checkout-duration-renew": "disable", "password-changer": "disable",
    "password-reconciliation": "disable", "password-heartbeat": "disable",
    "rdp-service-status": "down", "ssh-service-status": "down", "sftp-service-status": "down",
    "http-service-status": "down", "samba-service-status": "down", "telnet-service-status": "down",
    "vnc-service-status": "down", "ldaps-service-status": "down",
})
_POLICY_DEFAULTS = ("pwd-chg-use-policy-default", "heartbeat-use-policy-default")


class WindowsExecutionSecretError(RuntimeError):
    """Fixed non-disclosing refusal without selectors or credential values."""


def _machine(value: str) -> bytes:
    if type(value) is not str or _MACHINE.fullmatch(value) is None:
        raise ValueError
    return value.encode("ascii")


def _defaults_digest(policy_defaults: tuple[str, str]) -> str:
    if (type(policy_defaults) is not tuple or len(policy_defaults) != 2
            or any(type(value) is not str or value not in {"enable", "disable"} for value in policy_defaults)):
        raise ValueError
    guards = {**_GUARDS, **dict(zip(_POLICY_DEFAULTS, policy_defaults, strict=True))}
    return hashlib.sha256(json.dumps(guards, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode("ascii")).hexdigest()


class MachineQualifiedWindowsLocalLoader(_OpaqueC3Object):
    """Adapt one existing central loader; no alternate identity or cached value.

    Only a bare local username is admitted. The source username is erased after
    qualification, while ownership of the unchanged password passes to the
    existing C3 provider. Any load failure consumes this instance and clears all
    returned buffers. The parent's durable material claim remains mandatory.
    """

    def __init__(self, loader: CentralLabSecretCreateResolverLoader, *, machine_name: str) -> None:
        try:
            self._machine = _machine(machine_name)
            if (not callable(getattr(loader, "validate_prebound", None))
                    or not callable(getattr(loader, "load_secret_create_material_once", None))):
                raise ValueError
            self._loader, self._attempted, self._lock = loader, False, Lock()
        except Exception:
            raise WindowsExecutionSecretError(_ERROR) from None

    def validate_prebound(self) -> MaterialBindingStatus:
        with self._lock:
            try:
                if self._attempted:
                    return MaterialBindingStatus.UNAVAILABLE
                status = self._loader.validate_prebound()
                return status if type(status) is MaterialBindingStatus else MaterialBindingStatus.UNAVAILABLE
            except Exception:
                return MaterialBindingStatus.UNAVAILABLE

    def load_secret_create_material_once(self) -> tuple[bytearray, bytearray]:
        loaded: object = None
        qualified = bytearray()
        transferred = False
        try:
            with self._lock:
                if self._attempted:
                    raise ValueError
                self._attempted = True
            loaded = self._loader.load_secret_create_material_once()
            if (type(loaded) is not tuple or len(loaded) != 2
                    or any(type(value) is not bytearray for value in loaded)):
                raise ValueError
            username, password = loaded
            if (username is password or _LOCAL_USER.fullmatch(username) is None
                    or not _valid_material_view(memoryview(password).toreadonly())):
                raise ValueError
            qualified.extend(self._machine)
            qualified.extend(b"\\")
            qualified.extend(username)
            transferred = True
            return qualified, password
        except Exception:
            raise WindowsExecutionSecretError(_ERROR) from None
        finally:
            if type(loaded) in (tuple, list):
                for index, value in enumerate(cast(tuple[object, ...] | list[object], loaded)):
                    if type(value) is bytearray and not (transferred and index == 1):
                        _zeroize_mutable(value)
            if not transferred:
                _zeroize_mutable(qualified)


@dataclass(frozen=True, slots=True, repr=False)
class WindowsExecutionSecretDefaults(_OpaqueC3Object):
    serial_digest: str
    guards_digest: str
    policy_defaults: tuple[str, str]


def consume_windows_execution_defaults(raw: bytearray, *, expected_serial: str) -> WindowsExecutionSecretDefaults:
    """Require every fixed disabled default; decode no unselected/default material."""
    from . import secret_bulk_import_metadata as metadata
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= 1048576
                or type(expected_serial) is not str or re.fullmatch(r"[A-Za-z0-9]{1,128}", expected_serial) is None):
            raise ValueError
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        metadata._validate_json(raw, start, end, depth=0, budget=[50000])
        names = frozenset({"version", "build", "http_method", "http_status", "status", "path", "name",
            "vdom", "serial", "results", "action", "error", "schema_errors"})
        envelope = metadata._object_spans(raw, start, end, names)
        if "schema_errors" in envelope:
            raise ValueError
        expected = {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
            "status": "success", "path": "secret", "name": "database", "vdom": "root", "serial": expected_serial}
        if "action" in envelope:
            expected["action"] = "default"
        if "error" in envelope:
            expected["error"] = 0
        for name, wanted in expected.items():
            actual = metadata._scalar(raw, envelope[name])
            if type(actual) is not type(wanted) or actual != wanted:
                raise ValueError
        left, right = envelope["results"]
        if raw[left] == 91:
            rows = metadata._array(raw, (left, right), 1)
            if len(rows) != 1:
                raise ValueError
            left, right = rows[0]
        fields = metadata._object_spans(raw, left, right, frozenset(_GUARDS) | frozenset(_POLICY_DEFAULTS))
        for name, wanted in _GUARDS.items():
            actual = metadata._scalar(raw, fields[name])
            if type(actual) is not type(wanted) or actual != wanted:
                raise ValueError
        policy_defaults = tuple(metadata._scalar(raw, fields[name]) for name in _POLICY_DEFAULTS)
        if (len(policy_defaults) != 2 or any(type(value) is not str for value in policy_defaults)):
            raise ValueError
        policy = cast(tuple[str, str], policy_defaults)
        return WindowsExecutionSecretDefaults(hashlib.sha256(expected_serial.encode()).hexdigest(),
            _defaults_digest(policy), policy)
    except Exception:
        raise WindowsExecutionSecretError(_ERROR) from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


@dataclass(frozen=True, slots=True, repr=False)
class WindowsExecutionSecretBinding(_OpaqueC3Object):
    secret_name: str
    target_name: str
    target_address: str
    machine_name: str
    folder_id: int
    serial_digest: str
    private_nonce: str

    def __post_init__(self) -> None:
        try:
            if (type(self.secret_name) is not str or type(self.target_name) is not str
                    or re.fullmatch(r"MCPV4WinExec[0-9]{8}R[1-9][0-9]{0,2}", self.secret_name) is None
                    or re.fullmatch(r"MCPV4WinTarget[0-9]{8}R[1-9][0-9]{0,2}", self.target_name) is None
                    or type(self.folder_id) is not int or not 0 < self.folder_id <= 2147483647
                    or type(self.target_address) is not str):
                raise ValueError
            address = ipaddress.IPv4Address(self.target_address)
            if (str(address) != self.target_address or address.is_loopback or address.is_unspecified
                    or address.is_multicast or address.is_link_local):
                raise ValueError
            _machine(self.machine_name)
            require_digest(self.serial_digest, "serial_digest")
            require_digest(self.private_nonce, "private_nonce")
        except Exception:
            raise WindowsExecutionSecretError(_ERROR) from None

    @property
    def parameters_digest(self) -> str:
        self.__post_init__()
        return canonical_digest({"contract": CONTRACT, "secret_name": self.secret_name,
            "target_name": self.target_name, "target_address": self.target_address,
            "machine_name": self.machine_name, "folder_id": self.folder_id,
            "serial_digest": self.serial_digest, "private_nonce": self.private_nonce})


def build_windows_execution_secret_body(binding: WindowsExecutionSecretBinding,
        defaults: WindowsExecutionSecretDefaults, *, create_uuid: str,
        username: memoryview, password: memoryview) -> bytearray:
    """Build one associated-use credential record with interactive services down.

    No privilege changes occur on Windows here. The returned bytes and supplied
    material views stay inside the private C3 producer; the producer owns their
    disposal and must never expose them to MCP, logs or planning records.
    """
    with _MutableJSONBuffer() as body:
        try:
            if type(binding) is not WindowsExecutionSecretBinding or type(defaults) is not WindowsExecutionSecretDefaults:
                raise ValueError
            binding.__post_init__()
            if (defaults.serial_digest != binding.serial_digest
                    or defaults.guards_digest != _defaults_digest(defaults.policy_defaults)
                    or type(create_uuid) is not str or create_uuid != REQUEST_UUID):
                raise ValueError
            for value in (username, password):
                if (type(value) is not memoryview or type(value.obj) is not bytearray or not value.readonly
                        or not value.c_contiguous or value.format != "B" or not _valid_material_view(value)):
                    raise ValueError
            prefix = _machine(binding.machine_name) + b"\\"
            if (username.obj is password.obj or bytes(username[:len(prefix)]) != prefix
                    or _LOCAL_USER.fullmatch(username[len(prefix):]) is None):
                raise ValueError
            metadata = _proposed_metadata(binding, create_uuid)
            body.extend(json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")[:-1])
            # Native Secret.unparse omits Target-owned fields and sorts by name.
            body.extend(b',"field":[{"id":0,"name":"Password","value":')
            _append_material(body, password)
            body.extend(b'},{"id":0,"name":"Username","value":')
            _append_material(body, username)
            body.extend(b"}]}")
            return body.finish()
        except Exception:
            raise WindowsExecutionSecretError(_ERROR) from None


def _proposed_metadata(binding: WindowsExecutionSecretBinding, create_uuid: str) -> dict[str, str | int]:
    return {**_GUARDS, **dict.fromkeys(_POLICY_DEFAULTS, "disable"),
        "id": 0, "name": binding.secret_name, "target": binding.target_name,
        "folder": binding.folder_id, "template": "Windows Machine", "inherit-permission": "enable",
        "uuid": create_uuid, "server-info": "Inherit",
        "approval-profile": "", "need-approval": "disable", "need-approval-job": "disable",
        "av-profile": "", "av-scan": "disable", "bypass-ssh-filter-for-owner": "disable",
        "dlp-sensor": "", "dlp-status": "disable", "rdp-event-filter": "disable", "rdp-event-filter-profile": "",
        "secret-auth": "disable", "secret-auth-duration": 60, "secret-auth-server": "",
        "ssh-filter": "disable", "ssh-filter-profile": "", "winappfilter": "disable", "winappfilter-profile": "",
        "pwd-chg-sch-frequency": "month", "pwd-chg-sch-interval": 1, "pwd-chg-sch-month-day": "1",
        "pwd-chg-sch-month-type": "specific", "pwd-chg-sch-week-day": ""}


@dataclass(frozen=True, slots=True, repr=False)
class WindowsExecutionSecretMetadata(_OpaqueC3Object):
    native_secret_id: int
    native_uuid: str
    state_digest: str


def _project_windows_execution_secret_metadata(raw: bytearray, binding: WindowsExecutionSecretBinding,
        *, expected_secret_id: int, create_uuid: str,
        expected_native_uuid: str | None = None) -> WindowsExecutionSecretMetadata:
    """Borrow exact API GET/OK metadata; the private caller must erase the buffer.

    The prospective fixed API producer must qualify this detail route, preserve
    the original POST ACK and bind the returned native id. This metadata-only
    witness proves neither credential correctness nor original creation custody.
    The profile is associated-only: it never designates the Target's privileged
    account. A later probe Secret must carry its own explicit association.
    """
    from . import secret_bulk_import_metadata as metadata
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= 1048576
                or type(binding) is not WindowsExecutionSecretBinding
                or type(expected_secret_id) is not int or not 0 < expected_secret_id <= 2147483647
                or type(create_uuid) is not str or create_uuid != REQUEST_UUID):
            raise ValueError
        binding.__post_init__()
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        metadata._validate_json(raw, start, end, depth=0, budget=[50000])
        names = frozenset({"version", "build", "http_method", "http_status", "status", "path", "name",
            "vdom", "serial", "results", "mkey", "error", "action", "schema_errors"})
        envelope = metadata._object_spans(raw, start, end, names)
        if "schema_errors" in envelope:
            raise ValueError
        expected = {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
            "status": "OK", "path": "secret", "name": "database", "vdom": "root"}
        if "mkey" in envelope:
            expected["mkey"] = expected_secret_id
        if "error" in envelope:
            expected["error"] = 0
        if "action" in envelope:
            action = metadata._scalar(raw, envelope["action"])
            if action != "":
                raise ValueError
        for name, wanted in expected.items():
            actual = metadata._scalar(raw, envelope[name])
            if type(actual) is not type(wanted) or actual != wanted:
                raise ValueError
        serial = metadata._text(metadata._scalar(raw, envelope["serial"]), maximum=128)
        if hashlib.sha256(serial.encode()).hexdigest() != binding.serial_digest:
            raise ValueError
        left, right = envelope["results"]
        if raw[left] == 91:
            rows = metadata._array(raw, (left, right), 1)
            if len(rows) != 1:
                raise ValueError
            left, right = rows[0]
        wanted_fields = _proposed_metadata(binding, create_uuid)
        del wanted_fields["uuid"]
        wanted_fields["id"] = expected_secret_id
        wanted_fields.update(q_ref=0, q_static=False)
        fields = metadata._object_spans(raw, left, right,
            frozenset(wanted_fields) | {"target-info", "q_origin_key", "uuid"})
        if "q_origin_key" in fields:
            wanted_fields["q_origin_key"] = expected_secret_id
        for name, wanted in wanted_fields.items():
            actual = metadata._scalar(raw, fields[name])
            if type(actual) is not type(wanted) or actual != wanted:
                raise ValueError
        target = metadata._object_spans(raw, *fields["target-info"], frozenset({"priv_acct"}))
        privilege = metadata._scalar(raw, target["priv_acct"])
        if type(privilege) is not int or privilege != 0:
            raise ValueError
        native_uuid = metadata._scalar(raw, fields["uuid"])
        if (type(native_uuid) is not str or str(uuid.UUID(native_uuid)) != native_uuid
                or native_uuid == REQUEST_UUID
                or expected_native_uuid is not None and native_uuid != expected_native_uuid):
            raise ValueError
        digest = canonical_digest({"contract": CONTRACT, "parameters_digest": binding.parameters_digest,
            "native_id": expected_secret_id, "request_uuid": create_uuid, "native_uuid": native_uuid,
            "state": "associated-only-metadata-verified"})
        return WindowsExecutionSecretMetadata(expected_secret_id, native_uuid, digest)
    except Exception:
        raise WindowsExecutionSecretError(_ERROR) from None


def consume_windows_execution_secret_metadata(raw: bytearray, binding: WindowsExecutionSecretBinding,
        *, expected_secret_id: int, create_uuid: str,
        expected_native_uuid: str | None = None) -> WindowsExecutionSecretMetadata:
    """Consume selected metadata and erase on every exit; never decode material."""
    try:
        return _project_windows_execution_secret_metadata(raw, binding,
            expected_secret_id=expected_secret_id, create_uuid=create_uuid, expected_native_uuid=expected_native_uuid)
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)
