"""Fixed build-29 categorical getters, without material or execution surfaces.

Readers require separately qualified Owner/session producers. Configuration
digests stay private; these getters do not prove mutation or TOTP preservation.
"""

from collections.abc import Mapping
import json
from urllib.parse import quote

from .approval_profile_http_transport import _NAME, _disabled_principals, _is_fixed_approver
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_approval_build29_http_transport import (
    FortiPamSecretApprovalBuild29HttpTransport, _digest,
    _normalize_one_native_metadata_duplicate, _raw_members,
    _redact_material_members, _unique_members,
)
from .secret_approval_build29_projection_source import SecretApprovalBuild29ProfileInspection
from .secret_description_update_http_transport import _field_span
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, SecretApprovalProjectionInspection, _json_value_end,
    _redact_json_field_values, _skip_json_space, _zeroize_mutable,
)


_UNAVAILABLE = "The fixed build-29 approval metadata read is unavailable."
_PROFILE_PATH = "/api/v2/cmdb/secret/approval-profile/"
_PROFILE_ENVELOPE: dict[str, str | int] = {
    "version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
    "status": "success", "path": "secret", "name": "approval-profile", "vdom": "root",
}
_PRINCIPALS = ("first-group", "second-user", "second-group", "third-user", "third-group")
_PROFILE_REQUIRED = frozenset({
    "name", "q_origin_key", "type", "first-num", "first-user", *_PRINCIPALS,
    "self-approval", "auto-approval-schedule", "max-allowed-duration",
    "remote-group-email", "email-template", "approver-perm-req", "field",
})


class SecretApprovalBuild29MetadataReaderError(RuntimeError):
    """Non-disclosing refusal of a fixed metadata getter."""


class SecretApprovalBuild29ProfileReader:
    """Read one pinned single-tier Profile through its existing scoped Owner."""

    def __init__(
        self, owner: OwnerSessionMetadataTransport, *, expected_serial: str, profile_name: str,
    ) -> None:
        if (not isinstance(owner, OwnerSessionMetadataTransport)
                or type(expected_serial) is not str or not 1 <= len(expected_serial) <= 64
                or not expected_serial.isascii() or not expected_serial.isalnum()
                or type(profile_name) is not str or _NAME.fullmatch(profile_name) is None):
            raise SecretApprovalBuild29MetadataReaderError(_UNAVAILABLE)
        self._owner = owner
        self._serial = expected_serial
        self._name = profile_name
        self._path = _PROFILE_PATH + quote(profile_name, safe="")

    def readback(self, profile_name: str) -> SecretApprovalBuild29ProfileInspection:
        try:
            if type(profile_name) is not str or profile_name != self._name:
                raise ValueError
            with self._owner.authenticated():
                inspection, _ = self._active_read()
            if self._owner.logout_verified is not True:
                raise ValueError
            return inspection
        except Exception:
            raise SecretApprovalBuild29MetadataReaderError(_UNAVAILABLE) from None

    def current_configuration_digest(self) -> str:
        """Fresh private witness only inside the mutation's existing Owner session."""
        try:
            _, digest = self._active_read()
            return digest
        except Exception:
            raise SecretApprovalBuild29MetadataReaderError(_UNAVAILABLE) from None

    def _active_read(self) -> tuple[SecretApprovalBuild29ProfileInspection, str]:
        raw = bytearray()
        try:
            owner = self._owner
            if owner._client is None or owner._clock() >= owner._expires_at:
                raise ValueError
            with owner._client.stream("GET", self._path, headers={
                "Accept": "application/json", "Cache-Control": "no-cache, no-store",
            }) as response:
                if (type(response.status_code) is not int or response.status_code != 200
                        or response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                        != "application/json"):
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            field_start, field_end = _unique_raw_field_span(raw)
            if (raw[field_start] != 91 or raw[field_end - 1] != 93
                    or _skip_json_space(raw, field_start + 1) != field_end - 1):
                raise ValueError
            _redact_json_field_values(raw)
            _redact_material_members(raw)
            payload = json.loads(raw, object_pairs_hook=_unique_members, parse_constant=_reject_constant)
            if (type(payload) is not dict
                    or set(payload) != set(_PROFILE_ENVELOPE) | {"serial", "mkey", "revision", "results"}
                    or any(type(payload.get(name)) is not type(value) or payload[name] != value
                           for name, value in _PROFILE_ENVELOPE.items())
                    or payload["serial"] != self._serial or type(payload["serial"]) is not str
                    or payload["mkey"] != self._name or type(payload["mkey"]) is not str):
                raise ValueError
            row = _one_row(payload)
            if (not _PROFILE_REQUIRED <= set(row)
                    or row["name"] != self._name or type(row["name"]) is not str
                    or row["q_origin_key"] != self._name or type(row["q_origin_key"]) is not str
                    or row["type"] != "single" or type(row["type"]) is not str
                    or type(row["first-num"]) is not int or row["first-num"] != 1
                    or not _is_fixed_approver(row["first-user"])
                    or not all(_disabled_principals(row[name]) for name in _PRINCIPALS)
                    or row["self-approval"] != "disable"
                    or row["auto-approval-schedule"] != ""
                    or type(row["max-allowed-duration"]) is not int or row["max-allowed-duration"] != 0
                    or row["remote-group-email"] != "disable" or row["email-template"] != ""
                    or row["approver-perm-req"] != "none"):
                raise ValueError
            inspection = SecretApprovalBuild29ProfileInspection(True, True, True, True, True, True, True, True)
            digest = _digest({"version": "v7.0.0", "build": 29, "serial": self._serial, "configuration": row})
            if owner._client is None or owner._clock() >= owner._expires_at:
                raise ValueError
            return inspection, digest
        finally:
            _zeroize_mutable(raw)


class SecretApprovalBuild29ProjectionReader:
    """Read one explicitly bound Web or Linux approval posture."""

    def __init__(
        self, transport: FortiPamSecretApprovalBuild29HttpTransport, *, approval_profile_name: str | None = None,
    ) -> None:
        if not isinstance(transport, FortiPamSecretApprovalBuild29HttpTransport):
            raise SecretApprovalBuild29MetadataReaderError(_UNAVAILABLE)
        bound = None if transport._mutation is None else transport._mutation.approval_profile_name
        profile = bound if approval_profile_name is None else approval_profile_name
        if (type(profile) is not str or _NAME.fullmatch(profile) is None
                or bound is not None and profile != bound):
            raise SecretApprovalBuild29MetadataReaderError(_UNAVAILABLE)
        self._transport = transport
        self._profile = profile

    def inspect_approval_projection(
        self, folder_path: str, secret_name: str, approval_profile_name: str, *, expected_secret_id: int,
    ) -> SecretApprovalProjectionInspection:
        raw, redacted = bytearray(), bytearray()
        try:
            transport = self._transport
            if (transport._closed or type(folder_path) is not str or folder_path != transport._folder_path
                    or type(secret_name) is not str or secret_name != transport._identity["name"]
                    or type(approval_profile_name) is not str or approval_profile_name != self._profile
                    or type(expected_secret_id) is not int or expected_secret_id != transport._identity["id"]):
                raise ValueError
            owner = transport._owner
            with owner.authenticated():
                raw = transport._read_raw()
                _field_span(raw)  # Only prove the raw material array exists; never decode it.
                redacted.extend(raw)
                _normalize_one_native_metadata_duplicate(redacted)
                field_present = _redact_json_field_values(redacted)
                _redact_material_members(redacted)
                row = _one_row(json.loads(redacted, object_pairs_hook=_unique_members, parse_constant=_reject_constant))
                totp = row.get("totp-setting")
                from .target_contract import DEFAULT_TEMPLATE
                template = "Web Account" if transport._linux_target_name is None else DEFAULT_TEMPLATE
                target = "" if transport._linux_target_name is None else transport._linux_target_name
                if (type(row.get("template")) is not str or row["template"] != template
                        or type(row.get("target")) is not str or row["target"] != target
                        or type(totp) is not dict or type(totp.get("status")) is not str
                        or totp["status"] != "disable"):
                    raise ValueError
                projection, _ = transport._project_raw(raw)
                selected = projection["results"]
                if not isinstance(selected, Mapping) or selected["approval-profile"] not in ("", self._profile):
                    raise ValueError
                result = SecretApprovalProjectionInspection(
                    True, selected["need-approval"] == "enable", selected["need-approval-job"] == "enable",
                    selected["bypass-approval"] == "enable", selected["approval-profile"] == self._profile,
                    selected["approval-profile"] == "", field_present,
                )
            if owner.logout_verified is not True:
                raise ValueError
            return result
        except Exception:
            raise SecretApprovalBuild29MetadataReaderError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(raw)
            _zeroize_mutable(redacted)


def _unique_raw_field_span(raw: bytearray) -> tuple[int, int]:
    start = _skip_json_space(raw, 0)
    end = _json_value_end(raw, start)
    if _skip_json_space(raw, end) != len(raw):
        raise ValueError
    root: dict[str, tuple[int, int]] = {}
    for name, _, left, right, _ in _raw_members(raw, start, end):
        if name in root:
            raise ValueError
        root[name] = (left, right)
    left, right = root["results"]
    if raw[left] != 91 or raw[right - 1] != 93:
        raise ValueError
    row_start = _skip_json_space(raw, left + 1)
    row_end = _json_value_end(raw, row_start)
    if _skip_json_space(raw, row_end) != right - 1:
        raise ValueError
    row: dict[str, tuple[int, int]] = {}
    for name, _, left, right, _ in _raw_members(raw, row_start, row_end):
        if name in row:
            raise ValueError
        row[name] = (left, right)
    return row["field"]


def _one_row(payload: object) -> Mapping[str, object]:
    if not isinstance(payload, Mapping):
        raise ValueError
    rows = payload.get("results")
    if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
        raise ValueError
    return rows[0]


def _reject_constant(value: str) -> object:
    raise ValueError
