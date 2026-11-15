"""Private build-29 Launcher GET-detail qualification, with no write authority.

Source: API_SOURCES#bp008-approval-withdrawal-source-20261008 and the fixed
reviewer-native-detail-r3, detail-envelope-grammar, envelope-scalar-grammar and
detail-mkey-binding proofs. This exact GET shape differs from the sparse POST
reviewer view. Neither missing queue fields nor bearer refusal imply absence.

The caller must establish the actual product reviewer and device Date through
the same qualified session, and supply protected original creation bindings.
The relation qualifier checks current Secret->Profile->reviewer metadata against
the same binding. Neither qualifier establishes original Profile continuity,
session freshness, execution authority, DELETE ACK or access effects.
An expired consumed record is not made executable by its retained metadata.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json

from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, _json_value_end, _redact_json_field_values,
    _skip_json_space, _zeroize_mutable,
)
from .approval_profile_http_transport import _disabled_principals
from .secret_approval_build29_http_transport import (
    _raw_members, _redact_material_members, _validate_ack_json,
)
from .secret_approval_build29_metadata_reader import _unique_raw_field_span
from .secret_request_approval_revoke_contract import (
    qualify_secret_request_approval_revoke_native_tiers,
    secret_request_approval_revoke_launcher_window_available,
)

_UNAVAILABLE = "The fixed Launcher Request withdrawal detail is unavailable."
_CONTRACT = "secret-request-approval-revoke-build29-get-detail-v1"
_ENVELOPE = {
    "version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
    "status": "success", "path": "secret", "name": "request", "vdom": "root",
}
_ENVELOPE_KEYS = frozenset(_ENVELOPE) | {"results", "revision", "mkey", "serial"}
_REQUIRED_ROW = frozenset({
    "id", "q_origin_key", "secret-id", "user", "approval-profile", "request-type",
    "job-name", "final-status", "tier1-status", "tier1", "tier2", "tier3",
    "start-time", "expiration-time", "timezone",
})
_SECRET_ENVELOPE = {**_ENVELOPE, "status": "OK", "name": "database"}
_SECRET_ENVELOPE_KEYS = frozenset(_SECRET_ENVELOPE) | {"results", "serial"}
_PROFILE_ENVELOPE = {**_ENVELOPE, "name": "approval-profile"}
_OTHER_PRINCIPALS = ("first-group", "second-user", "second-group", "third-user", "third-group")


class SecretRequestApprovalRevokeDetailContractError(ValueError):
    """Stable refusal without upstream data, identifiers or exception text."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestApprovalRevokeDetailBinding:
    """Private selectors, supplied from independently protected original records.

    Construction validates grammar only, never provenance or an execution right.
    The original Profile must not be inferred solely from current configuration.
    """

    request_id: int
    secret_id: int
    requester: str
    approval_profile_name: str
    original_reviewer: str
    source_serial: str

    def __post_init__(self) -> None:
        if (any(type(value) is not int or not 0 < value <= 2_147_483_647
                for value in (self.request_id, self.secret_id))
                or not _identity(self.requester, 128)
                or not _identity(self.approval_profile_name, 128)
                or not _identity(self.original_reviewer, 255)
                or not _identity(self.source_serial, 64)
                or self.requester == self.original_reviewer):
            raise SecretRequestApprovalRevokeDetailContractError(_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestApprovalRevokeDetailWitness:
    """Private immutable digests only; never an authority or dispatch permit."""

    private_binding_digest: str
    private_native_metadata_digest: str
    private_tier_digest: str


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestApprovalRevokeRelationWitness:
    """Current private metadata preservation, without original provenance or authority."""

    private_binding_digest: str
    private_secret_metadata_digest: str
    private_profile_metadata_digest: str


def qualify_secret_request_approval_revoke_secret_profile_relation(
    secret_native_json: bytes | bytearray,
    profile_native_json: bytes | bytearray,
    *, binding: SecretRequestApprovalRevokeDetailBinding,
    authenticated_reviewer: str,
) -> SecretRequestApprovalRevokeRelationWitness:
    """Check two bounded current reads, redacting material before value decoding.

    The caller supplies same-session qualified actor/Role, freshness and protected
    original bindings. The matching binding digest joins this result to separate
    Request detail/window qualification. Current Profile configuration cannot
    replace the same-parent original creation witness. No duplicate normalization
    is performed here, even if a qualified upstream reader permits a fixed case.
    """
    try:
        if (type(binding) is not SecretRequestApprovalRevokeDetailBinding
                or type(authenticated_reviewer) is not str
                or authenticated_reviewer != binding.original_reviewer):
            raise ValueError
        payloads = []
        for index, native in enumerate((secret_native_json, profile_native_json)):
            if type(native) not in (bytes, bytearray) or not 0 < len(native) <= MAX_RESPONSE_BYTES:
                raise ValueError
            raw = bytearray(native)
            try:
                start = _skip_json_space(raw, 0)
                end = _json_value_end(raw, start)
                if _skip_json_space(raw, end) != len(raw):
                    raise ValueError
                # Existing bounded JSON syntax validator never decodes values.
                _validate_ack_json(raw, start, end)
                _reject_raw_duplicates(raw, start, end)
                if index == 1:
                    left, right = _unique_raw_field_span(raw)
                    if (raw[left] != 91 or raw[right - 1] != 93
                            or _skip_json_space(raw, left + 1) != right - 1):
                        raise ValueError
                _redact_json_field_values(raw)
                _redact_material_members(raw)
                if index == 1:
                    # Only this exact original empty array was verified above;
                    # preserve it rather than deriving emptiness from redacted null.
                    left, right = _unique_raw_field_span(raw)
                    raw[left:right] = b"[]"
                payloads.append(json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_members,
                                           parse_constant=_reject_constant))
            finally:
                _zeroize_mutable(raw)
        secret, profile = payloads
        for payload, envelope, keys in ((secret, _SECRET_ENVELOPE, _SECRET_ENVELOPE_KEYS),
                                        (profile, _PROFILE_ENVELOPE, _ENVELOPE_KEYS)):
            if (type(payload) is not dict or set(payload) != keys
                    or any(type(payload.get(key)) is not type(value) or payload[key] != value
                           for key, value in envelope.items())
                    or type(payload["serial"]) is not str or payload["serial"] != binding.source_serial
                    or type(payload["results"]) is not list or len(payload["results"]) != 1
                    or type(payload["results"][0]) is not dict):
                raise ValueError
        secret_row = secret["results"][0]
        expected_secret = {
            "id": binding.secret_id, "q_origin_key": binding.secret_id,
            "need-approval": "enable", "bypass-approval": "disable",
            "approval-profile": binding.approval_profile_name,
        }
        if any(type(secret_row.get(key)) is not type(value) or secret_row[key] != value
               for key, value in expected_secret.items()):
            raise ValueError
        if type(profile["mkey"]) is not str or profile["mkey"] != binding.approval_profile_name:
            raise ValueError
        profile_row = profile["results"][0]
        expected_profile = {
            "name": binding.approval_profile_name, "q_origin_key": binding.approval_profile_name,
            "type": "single", "first-num": 1, "self-approval": "disable",
            "auto-approval-schedule": "", "max-allowed-duration": 0,
            "remote-group-email": "disable", "email-template": "", "approver-perm-req": "none",
        }
        if (any(type(profile_row.get(key)) is not type(value) or profile_row[key] != value
                for key, value in expected_profile.items())
                or not all(key in profile_row and _disabled_principals(profile_row[key])
                           for key in _OTHER_PRINCIPALS)
                or type(profile_row.get("field")) is not list or profile_row["field"] != []):
            raise ValueError
        first_user = profile_row.get("first-user")
        if (type(first_user) is not list or len(first_user) != 1 or type(first_user[0]) is not dict
                or set(first_user[0]) != {"name", "q_origin_key"}
                or any(type(value) is not str or value != binding.original_reviewer
                       for value in first_user[0].values())):
            raise ValueError
        return SecretRequestApprovalRevokeRelationWitness(
            private_binding_digest=_digest({"contract": _CONTRACT, "binding": asdict(binding)}),
            private_secret_metadata_digest=_digest(secret),
            private_profile_metadata_digest=_digest(profile),
        )
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError, RuntimeError, IndexError):
        raise SecretRequestApprovalRevokeDetailContractError(_UNAVAILABLE) from None


def _reject_raw_duplicates(raw: bytearray, start: int, end: int, depth: int = 0) -> None:
    """Inspect keys only, including inside material that must never be decoded."""
    if depth > 64:
        raise ValueError
    if raw[start] == 123:
        seen: set[str] = set()
        for key, _, left, right, _ in _raw_members(raw, start, end):
            if key in seen:
                raise ValueError
            seen.add(key)
            _reject_raw_duplicates(raw, left, right, depth + 1)
    elif raw[start] == 91:
        cursor = _skip_json_space(raw, start + 1)
        while cursor < end - 1:
            right = _json_value_end(raw, cursor)
            if right >= end:
                raise ValueError
            _reject_raw_duplicates(raw, cursor, right, depth + 1)
            cursor = _skip_json_space(raw, right)
            if cursor == end - 1:
                return
            if raw[cursor] != 44:
                raise ValueError
            cursor = _skip_json_space(raw, cursor + 1)


def qualify_secret_request_approval_revoke_get_detail(
    native_json: bytes | bytearray,
    *, binding: SecretRequestApprovalRevokeDetailBinding,
    authenticated_reviewer: str,
    server_time: datetime | None,
) -> SecretRequestApprovalRevokeDetailWitness:
    """Qualify one bounded duplicate-free native GET, returning no raw values.

    The binding/profile and authenticated actor are private trusted inputs, not
    caller assertions that this pure function can authenticate. A later complete
    chain must independently verify fresh native Secret/Profile joins and the
    original creation witness before permitting any dispatch.
    """
    try:
        if (type(binding) is not SecretRequestApprovalRevokeDetailBinding
                or type(authenticated_reviewer) is not str
                or authenticated_reviewer != binding.original_reviewer
                or type(native_json) not in (bytes, bytearray)
                or not 0 < len(native_json) <= MAX_RESPONSE_BYTES):
            raise ValueError
        raw = bytearray(native_json)
        try:
            start = _skip_json_space(raw, 0)
            end = _json_value_end(raw, start)
            if _skip_json_space(raw, end) != len(raw):
                raise ValueError
            _validate_ack_json(raw, start, end)
            _reject_raw_duplicates(raw, start, end)
            _redact_json_field_values(raw)
            _redact_material_members(raw)
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_members,
                                 parse_constant=_reject_constant)
        finally:
            _zeroize_mutable(raw)
        if (type(payload) is not dict or set(payload) != _ENVELOPE_KEYS
                or any(type(payload.get(key)) is not type(value) or payload[key] != value
                       for key, value in _ENVELOPE.items())
                or type(payload["serial"]) is not str or payload["serial"] != binding.source_serial
                or type(payload["mkey"]) is not str or payload["mkey"] != str(binding.request_id)
                or type(payload["revision"]) is not str or not payload["revision"]
                or len(payload["revision"].encode("utf-8")) > 128
                or type(payload["results"]) is not list or len(payload["results"]) != 1):
            raise ValueError
        row = payload["results"][0]
        if type(row) is not dict or not _REQUIRED_ROW <= set(row):
            raise ValueError
        expected = {
            "id": binding.request_id, "q_origin_key": binding.request_id,
            "secret-id": binding.secret_id, "user": binding.requester,
            "approval-profile": binding.approval_profile_name,
            "request-type": "launcher", "job-name": "",
            "final-status": "approved", "tier1-status": "approved",
        }
        if any(type(row.get(key)) is not type(value) or row[key] != value
               for key, value in expected.items()):
            raise ValueError
        tier = qualify_secret_request_approval_revoke_native_tiers(
            {key: row[key] for key in ("tier1", "tier2", "tier3")},
            requester=binding.requester, authenticated_reviewer=authenticated_reviewer,
        )
        # The qualified native GET has strings; numeric shapes belong to the
        # independently observed POST reviewer view, not this GET profile.
        if (type(row["tier1"][0]["update-time"]) is not str
                or type(row["start-time"]) is not str or type(row["expiration-time"]) is not str):
            raise ValueError
        if not secret_request_approval_revoke_launcher_window_available(
            {key: row[key] for key in ("start-time", "expiration-time", "timezone")},
            server_time=server_time,
        ):
            raise ValueError
        return SecretRequestApprovalRevokeDetailWitness(
            private_binding_digest=_digest({"contract": _CONTRACT, "binding": asdict(binding)}),
            private_native_metadata_digest=_digest(payload),
            private_tier_digest=tier.private_digest,
        )
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError, RuntimeError, IndexError):
        raise SecretRequestApprovalRevokeDetailContractError(_UNAVAILABLE) from None


def _identity(value: object, max_bytes: int) -> bool:
    if type(value) is not str or not value or value != value.strip():
        return False
    try:
        return (len(value.encode("utf-8")) <= max_bytes
                and not any(ord(char) < 32 or ord(char) == 127 for char in value))
    except UnicodeError:
        return False


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError


def _digest(value: object) -> str:
    content = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(content).hexdigest()
