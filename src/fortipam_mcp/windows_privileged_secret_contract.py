"""Private privileged-credential request for an existing Windows Target.

This is a distinct fixed profile, not an option on the execution or Collector
profiles. It supplies no source admission, material reader, dispatcher, Tool or
recovery authority. A producer must first qualify the original subject, exact
existing Target/association state, owned Folder, M4/C3 lease and full original
birth/readback plus independent recovery. Context digests alone attest none of
those properties. Credential views and returned bytes remain private.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
import uuid

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _append_material, _valid_material_view
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from . import secret_bulk_import_metadata as parser
from .local_user_reset_projection import _object_spans
from .target_lifecycle_dependencies import _spans, _one
from .windows_execution_secret_contract import (
    REQUEST_UUID, WindowsExecutionSecretDefaults, _GUARDS, _LOCAL_USER,
    _POLICY_DEFAULTS, _defaults_digest, _machine,
)

CONTRACT = "fortipam-700-build29-windows-privileged-existing-target-secret-private-v1"
_ERROR = "The private Windows privileged Secret request is unavailable."
_NAME = re.compile(r"MCPV4SvcPriv[0-9]{8}R[1-9][0-9]{0,2}\Z")
_SELECTOR = re.compile(r"[^\x00-\x1f\x7f]{1,127}\Z")


class WindowsPrivilegedSecretError(RuntimeError):
    """Fixed non-disclosing refusal without selectors or material."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsPrivilegedSecretBinding(_OpaqueC3Object):
    secret_name: str
    target_name: str
    target_address: str
    machine_name: str
    folder_id: int
    serial_digest: str
    target_reference_context_digest: str
    subject_context_digest: str
    association_context_digest: str
    folder_context_digest: str
    private_nonce: str

    def __post_init__(self) -> None:
        try:
            if (type(self.secret_name) is not str or _NAME.fullmatch(self.secret_name) is None
                    or type(self.target_name) is not str or _SELECTOR.fullmatch(self.target_name) is None
                    or self.target_name != self.target_name.strip()
                    or self.target_name.startswith("MCPV4WinTarget")
                    or len(self.target_name.encode("utf-8")) > 127
                    or type(self.folder_id) is not int or not 0 < self.folder_id <= 2147483647
                    or type(self.target_address) is not str):
                raise ValueError
            address = ipaddress.IPv4Address(self.target_address)
            if (str(address) != self.target_address or address.is_loopback or address.is_unspecified
                    or address.is_multicast or address.is_link_local):
                raise ValueError
            _machine(self.machine_name)
            for value in (self.serial_digest, self.target_reference_context_digest,
                          self.subject_context_digest, self.association_context_digest,
                          self.folder_context_digest, self.private_nonce):
                require_digest(value, "private_context_digest")
        except Exception:
            raise WindowsPrivilegedSecretError(_ERROR) from None

    @property
    def parameters_digest(self) -> str:
        self.__post_init__()
        return canonical_digest({
            "contract": CONTRACT, "secret_name": self.secret_name, "target_name": self.target_name,
            "target_address": self.target_address, "machine_name": self.machine_name,
            "folder_id": self.folder_id, "serial_digest": self.serial_digest,
            "target_reference_context_digest": self.target_reference_context_digest,
            "subject_context_digest": self.subject_context_digest,
            "association_context_digest": self.association_context_digest,
            "folder_context_digest": self.folder_context_digest, "private_nonce": self.private_nonce,
        })

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT, fixed_privileged_account_proposal=True,
                    interactive_services_requested=False, automatic_password_lifecycle_requested=False,
                    original_target_ownership_required=False, existing_target_adoption_authorized=False,
                    target_source_qualified=False, subject_source_qualified=False,
                    privilege_association_scope_qualified=False, effective_permission_qualified=False,
                    material_source_qualified=False, original_birth_qualified=False,
                    independent_recovery_qualified=False, execution_authorized=False,
                    runtime_registered=False, private_values_returned=False)


def _metadata(binding: WindowsPrivilegedSecretBinding) -> dict[str, object]:
    # This fixed proposal is reachable only through the distinct binding type.
    # The existing execution profile and its disabled privilege guard are intact.
    return {**_reference_metadata(binding.secret_name, binding.target_name, binding.folder_id),
            "target-privilege-account": "enable"}


def _reference_metadata(secret_name: str, target_name: str, folder_id: int) -> dict[str, object]:
    """Shared fixed noninteractive proposal; privilege stays disabled by default."""
    return {
        **_GUARDS, **dict.fromkeys(_POLICY_DEFAULTS, "disable"),
        "id": 0, "name": secret_name, "target": target_name,
        "folder": folder_id, "template": "Windows Machine",
        "inherit-permission": "enable", "uuid": REQUEST_UUID, "server-info": "Inherit",
        "approval-profile": "", "need-approval": "disable", "need-approval-job": "disable",
        "av-profile": "", "av-scan": "disable", "bypass-ssh-filter-for-owner": "disable",
        "dlp-sensor": "", "dlp-status": "disable",
        "rdp-event-filter": "disable", "rdp-event-filter-profile": "",
        "secret-auth": "disable", "secret-auth-duration": 60, "secret-auth-server": "",
        "ssh-filter": "disable", "ssh-filter-profile": "",
        "winappfilter": "disable", "winappfilter-profile": "",
        "pwd-chg-sch-frequency": "month", "pwd-chg-sch-interval": 1,
        "pwd-chg-sch-month-day": "1", "pwd-chg-sch-month-type": "specific",
        "pwd-chg-sch-week-day": "",
        "dependency": [],
    }


def _compile_reference_body(metadata: dict[str, object], machine_name: str, *,
        username: memoryview, password: memoryview) -> bytearray:
    """Private byte compiler shared by two closed existing-Target profiles."""
    with _MutableJSONBuffer() as body:
        try:
            for view in (username, password):
                if (type(view) is not memoryview or type(view.obj) is not bytearray or not view.readonly
                        or not view.c_contiguous or view.format != "B" or not _valid_material_view(view)):
                    raise ValueError
            prefix = _machine(machine_name) + b"\\"
            if (username.obj is password.obj or bytes(username[:len(prefix)]) != prefix
                    or _LOCAL_USER.fullmatch(username[len(prefix):]) is None):
                raise ValueError
            body.extend(json.dumps(metadata, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=True).encode("ascii")[:-1])
            body.extend(b',"field":[{"id":0,"name":"Password","value":')
            _append_material(body, password)
            body.extend(b'},{"id":0,"name":"Username","value":')
            _append_material(body, username)
            body.extend(b"}]}")
            return body.finish()
        except BaseException:
            raise


def build_windows_privileged_secret_body(
    binding: WindowsPrivilegedSecretBinding, defaults: WindowsExecutionSecretDefaults, *,
    create_uuid: str, username: memoryview, password: memoryview,
) -> bytearray:
    """Borrow qualified-local views for the fixed privileged proposal only.

    Input disposal belongs to the caller. The returned body must clear after its
    one original authorized dispatch. Host is owned by the Target and omitted.
    """
    try:
        if type(binding) is not WindowsPrivilegedSecretBinding or type(defaults) is not WindowsExecutionSecretDefaults:
            raise ValueError
        binding.__post_init__()
        if (defaults.serial_digest != binding.serial_digest
                or defaults.guards_digest != _defaults_digest(defaults.policy_defaults)
                or type(create_uuid) is not str or create_uuid != REQUEST_UUID):
            raise ValueError
        return _compile_reference_body(_metadata(binding), binding.machine_name, username=username, password=password)
    except Exception:
        raise WindowsPrivilegedSecretError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class WindowsPrivilegedSecretMetadata(_OpaqueC3Object):
    """Supplied fixed postcondition only, never original birth or material proof."""
    native_secret_id: int
    native_uuid: str
    password_field_id: int
    metadata_digest: str

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT, supplied_fixed_metadata_matched=True,
                    supplied_privileged_reference_matches_selected_secret=True,
                    source_completeness_qualified=False, source_provenance_qualified=False,
                    original_birth_qualified=False, material_consistency_qualified=False,
                    target_preservation_qualified=False, effective_permission_qualified=False,
                    independent_recovery_qualified=False, execution_authorized=False,
                    runtime_registered=False, private_values_returned=False)


def consume_windows_privileged_secret_metadata(
    raw: bytearray, binding: WindowsPrivilegedSecretBinding, *, expected_secret_id: int,
    expected_native_uuid: str | None = None,
) -> WindowsPrivilegedSecretMetadata:
    """Consume one fixed GET/OK frame without decoding credential values.

    All fixed proposed guards must match and target-info must point to the
    selected native Secret ID. That ID/UUID must later come from the original
    dispatch and custody, not lookup/adoption. Every supplied byte clears on
    success, refusal or interruption. Unknown configuration is not a complete
    preservation witness; original full-row/material custody remains separate.
    """
    try:
        return _project_windows_privileged_secret_metadata(raw, binding,
            expected_secret_id=expected_secret_id, expected_native_uuid=expected_native_uuid)
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


def _project_windows_privileged_secret_metadata(
    raw: bytearray, binding: WindowsPrivilegedSecretBinding, *, expected_secret_id: int,
    expected_native_uuid: str | None = None,
) -> WindowsPrivilegedSecretMetadata:
    """Borrow the full frame inside original custody; the caller must erase it."""
    try:
        if type(binding) is not WindowsPrivilegedSecretBinding:
            raise ValueError
        binding.__post_init__()
        native_uuid, field_id, digest = _project_reference_metadata(raw,
            serial_digest=binding.serial_digest, parameters_digest=binding.parameters_digest,
            target_address=binding.target_address,
            expected_metadata=_metadata(binding), contract=CONTRACT,
            expected_association_id=expected_secret_id, expected_secret_id=expected_secret_id,
            expected_native_uuid=expected_native_uuid)
        return WindowsPrivilegedSecretMetadata(expected_secret_id, native_uuid, field_id, digest)
    except Exception:
        raise WindowsPrivilegedSecretError(_ERROR) from None


def _project_reference_metadata(raw: bytearray, *, serial_digest: str, parameters_digest: str, target_address: str,
        expected_metadata: dict[str, object], contract: str, expected_association_id: int,
        expected_secret_id: int, expected_native_uuid: str | None = None) -> tuple[str, int, str]:
    """Private framing grammar; closed callers supply their exact fixed proposal."""
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= 1048576
                or type(expected_secret_id) is not int or not 0 < expected_secret_id <= 2147483647
                or type(expected_association_id) is not int or not 0 <= expected_association_id <= 2147483647):
            raise ValueError
        _spans(raw)
        start = _skip_json_space(raw, 0)
        fields = _object_spans(raw, start, _json_value_end(raw, start))
        wanted: dict[str, object] = dict(version="v7.0.0", build=29, http_method="GET", http_status=200,
                                         status="OK", path="secret", name="database", vdom="root")
        if "schema_errors" in fields:
            raise ValueError
        if "mkey" in fields:
            wanted["mkey"] = expected_secret_id
        if "error" in fields:
            wanted["error"] = 0
        if "action" in fields:
            wanted["action"] = ""
        if "limit_reached" in fields:
            wanted["limit_reached"] = False
        for name in ("size", "matched_count", "filtered_count"):
            if name in fields:
                wanted[name] = 1
        if "next_idx" in fields:
            value = parser._scalar(raw, fields["next_idx"])
            if type(value) is not int or value not in (0, 1):
                raise ValueError
        for name, expected in wanted.items():
            actual = parser._scalar(raw, fields[name])
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError
        serial = parser._text(parser._scalar(raw, fields["serial"]), maximum=128)
        if hashlib.sha256(serial.encode()).hexdigest() != serial_digest:
            raise ValueError
        row = _object_spans(raw, *_one(raw, fields["results"]))
        wanted = dict(expected_metadata)
        del wanted["uuid"]
        wanted["id"] = expected_secret_id
        if "q_origin_key" in row:
            wanted["q_origin_key"] = expected_secret_id
        for name, expected in wanted.items():
            if type(expected) is list:
                if parser._array(raw, row[name], 0):
                    raise ValueError
            else:
                actual = parser._scalar(raw, row[name])
                if type(actual) is not type(expected) or actual != expected:
                    raise ValueError
        if parser._array(raw, row["subscriber"], 0):
            raise ValueError
        target = _object_spans(raw, *row["target-info"])
        privilege = parser._scalar(raw, target["priv_acct"])
        if type(privilege) is not int or privilege != expected_association_id:
            raise ValueError
        native_uuid = parser._scalar(raw, row["uuid"])
        if (type(native_uuid) is not str or str(uuid.UUID(native_uuid)) != native_uuid
                or native_uuid == REQUEST_UUID
                or expected_native_uuid is not None and native_uuid != expected_native_uuid):
            raise ValueError
        slots: dict[str, int] = {}
        identifiers: set[int] = set()
        for span in parser._array(raw, row["field"], 3):
            entry = _object_spans(raw, *span)
            slot_name = parser._scalar(raw, entry["name"])
            identifier = parser._integer(parser._scalar(raw, entry["id"]))
            if (type(slot_name) is not str or slot_name not in {"Host", "Username", "Password"}
                    or slot_name in slots or identifier in identifiers or raw[entry["value"][0]] != 34):
                raise ValueError
            if slot_name == "Host" and raw[slice(*entry["value"])] != json.dumps(target_address).encode("ascii"):
                raise ValueError
            slots[slot_name] = identifier
            identifiers.add(identifier)
        if not {"Username", "Password"} <= slots.keys():
            raise ValueError
        digest = canonical_digest(dict(contract=contract, parameters_digest=parameters_digest,
            native_secret_id=expected_secret_id, native_uuid=native_uuid, password_field_id=slots["Password"],
            state="fixed-reference-metadata-matched"))
        return native_uuid, slots["Password"], digest
    except Exception:
        raise WindowsPrivilegedSecretError(_ERROR) from None
