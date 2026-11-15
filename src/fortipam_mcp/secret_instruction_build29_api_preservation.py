"""Inactive private API preservation consumers; no transport or authority.

Source qualification, exact bound requests and original fixture custody stay
with the trusted producer. No cleartext value is decoded, returned or retained.
"""
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import re
import uuid

from . import secret_bulk_import_metadata as metadata
from .instruction_profile_contract import _NAME
from .secret_approval_build29_native_preservation import _qualify_bracket
from .secret_approval_build29_totp_boundary import (
    SecretApprovalBuild29TotpWitness, _member_spans, _pinned_tokens,
)
from .secret_approval_build29_web_fields import _slots
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

_ERROR = "The private Secret Instruction API preservation witness is unavailable."
_MAX_BYTES = 524_288
_KEY_DOMAIN = b"instruction-clear-source-key/v1\x00"
_MATERIAL_DOMAIN = b"instruction-clear-json-token/v1\x00"
_DOMAIN = b"fortipam-700-build29-instruction-full-api-preservation-v1\x00"
_IDENTITY = frozenset({"id", "name", "folder", "template", "target", "uuid"})
_SELECTED = _IDENTITY | {"instruction-profile", "field", "totp-setting", "q_origin_key"}
_ENVELOPE = frozenset({"version", "build", "path", "name", "http_method", "status", "http_status",
                       "serial", "vdom", "results", "error", "action", "schema_errors",
                       "size", "matched_count", "filtered_count", "next_idx", "limit_reached", "revision"})


class SecretInstructionBuild29ApiPreservationError(ValueError):
    """Categorical refusal without private input values or upstream details."""

    def __init__(self) -> None:
        super().__init__(_ERROR)


@dataclass(frozen=True, slots=True, repr=False)
class SecretInstructionBuild29CredentialWitness:
    """Private clear-response token witness; its type is not provenance proof."""

    secret_id: int
    field_id: int
    key_digest: str
    material_digest: str


@dataclass(frozen=True, slots=True, repr=False)
class SecretInstructionBuild29ApiPreservationWitness:
    """Private complete-response digest, with mandatory independent materials."""

    preservation_digest: str


def _key(key: bytes | bytearray, raw: bytearray) -> None:
    if type(key) not in (bytes, bytearray) or key is raw or not 32 <= len(key) <= 128:
        raise ValueError


def _document(raw: bytearray, maximum: int = _MAX_BYTES) -> tuple[int, int]:
    if type(raw) is not bytearray or not 0 < len(raw) <= maximum:
        raise ValueError
    start = _skip_json_space(raw, 0)
    end = _json_value_end(raw, start)
    if _skip_json_space(raw, end) != len(raw):
        raise ValueError
    metadata._validate_json(raw, start, end, depth=0, budget=[50_000])
    return start, end


def _credential_pinned_tokens(envelope: Mapping[str, str | int], *,
        expected_field_id: int | None = None) -> dict[str, tuple[bytes, bytes]]:
    """Pin the observed Password field selector without widening TOTP envelopes."""
    if not isinstance(envelope, Mapping):
        raise ValueError
    values = dict(envelope)
    has_field = "field-id" in values
    field_id = values.pop("field-id", None)
    if has_field:
        metadata._integer(field_id)
        if expected_field_id is not None and field_id != expected_field_id:
            raise ValueError
    pins = _pinned_tokens(values)
    if has_field:
        pins["field-id"] = (b'"field-id"', str(field_id).encode("ascii"))
    return pins


def consume_secret_instruction_build29_credential_response(
    raw: bytearray, *, expected_secret_id: int, expected_field_id: int,
    http_status: int, content_type: str, expected_envelope: Mapping[str, str | int],
    witness_key: bytes | bytearray,
) -> SecretInstructionBuild29CredentialWitness:
    """Consume one independently source-qualified clear Password response.

    The exact observed envelope must be pinned by the private producer, which
    must bind the actual request to this Secret and Password field. Successful
    Bearer retrieval has not been qualified by this pure consumer. A TOTP source
    cannot be substituted for a Password request merely because envelopes match.

    Hash the complete valid JSON string token without scalar decoding. Arbitrary
    UTF-8, escapes and empty strings are supported. Alternate equivalent JSON
    renderings deliberately produce different digests and fail comparisons.
    Missing/null results never mean an empty password. All raw bytes are wiped.
    """
    try:
        _key(witness_key, raw)
        for identifier in (expected_secret_id, expected_field_id):
            metadata._integer(identifier)
        if (type(http_status) is not int or http_status != 200 or type(content_type) is not str
                or content_type.split(";", 1)[0].strip().lower() != "application/json"):
            raise ValueError
        required = {"secret-id": expected_secret_id, "http_method": "POST", "http_status": 200, "status": "OK"}
        if (not isinstance(expected_envelope, Mapping) or "msg" not in expected_envelope
                or any(type(expected_envelope.get(key)) is not type(value)
                       or expected_envelope[key] != value for key, value in required.items())):
            raise ValueError
        pins = _credential_pinned_tokens(expected_envelope, expected_field_id=expected_field_id)
        start, end = _document(raw, 16_384)
        spans = _member_spans(raw, start, end, pins)
        if set(spans) != set(pins):
            raise ValueError
        for name, (_, expected_token) in pins.items():
            if name != "results":
                with memoryview(raw)[slice(*spans[name])] as pin_value:
                    if not hmac.compare_digest(pin_value, expected_token):
                        raise ValueError
        left, right = spans["results"]
        if raw[left] != 34 or right - left > 8194:
            raise ValueError
        digest = hmac.new(witness_key, digestmod=hashlib.sha256)
        digest.update(_MATERIAL_DOMAIN)
        with memoryview(raw)[left:right] as json_token:
            digest.update(json_token)
        return SecretInstructionBuild29CredentialWitness(expected_secret_id, expected_field_id,
            hmac.new(witness_key, _KEY_DOMAIN, hashlib.sha256).hexdigest(), digest.hexdigest())
    except Exception:
        raise SecretInstructionBuild29ApiPreservationError() from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


def _credential_bracket(before: SecretInstructionBuild29CredentialWitness,
        after: SecretInstructionBuild29CredentialWitness, *, secret_id: int, field_id: int,
        key: bytes | bytearray) -> None:
    key_digest = hmac.new(key, _KEY_DOMAIN, hashlib.sha256).hexdigest()
    for witness in (before, after):
        if (type(witness) is not SecretInstructionBuild29CredentialWitness
                or type(witness.secret_id) is not int or witness.secret_id != secret_id
                or type(witness.field_id) is not int or witness.field_id != field_id
                or type(witness.key_digest) is not str or not hmac.compare_digest(witness.key_digest, key_digest)
                or type(witness.material_digest) is not str
                or re.fullmatch(r"[a-f0-9]{64}", witness.material_digest) is None):
            raise ValueError
    if not hmac.compare_digest(before.material_digest, after.material_digest):
        raise ValueError


def _qualify_web_detail(raw: bytearray, *, identity: Mapping[str, object], serial_digest: str,
        instruction_profile_name: str, field: bytearray,
) -> tuple[int, int, dict[str, tuple[int, int]], int, tuple[int, int]]:
    """Validate one full detail frame without manufacturing material evidence.

    The private caller owns and must wipe both mutable buffers on every exit.
    The field workspace must be empty. Returned spans and slot id are private
    framing metadata, never preservation, source or operation authority.
    """
    if type(field) is not bytearray or field is raw or field:
        raise ValueError
    if not isinstance(identity, Mapping) or set(identity) != _IDENTITY:
        raise ValueError
    for name in ("id", "folder"):
        metadata._integer(identity[name])
    for name in ("name", "template", "uuid"):
        metadata._text(identity[name])
    if (identity["template"] != "Web Account" or type(identity["target"]) is not str or identity["target"] != ""
            or type(serial_digest) is not str or metadata._DIGEST.fullmatch(serial_digest) is None
            or type(instruction_profile_name) is not str
            or instruction_profile_name and _NAME.fullmatch(instruction_profile_name) is None):
        raise ValueError
    native_uuid = identity["uuid"]
    if (type(native_uuid) is not str or str(uuid.UUID(native_uuid)) != native_uuid
            or uuid.UUID(native_uuid).int == 0):
        raise ValueError
    start, end = _document(raw)
    root = metadata._object_spans(raw, start, end, _ENVELOPE)
    for name, expected in {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
                           "status": "OK", "path": "secret", "name": "database", "vdom": "root"}.items():
        actual = metadata._scalar(raw, root[name])
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError
    serial = metadata._text(metadata._scalar(raw, root["serial"]), maximum=128)
    if hashlib.sha256(serial.encode()).hexdigest() != serial_digest or {"action", "schema_errors"} & root.keys():
        raise ValueError
    if "error" in root:
        value = metadata._scalar(raw, root["error"])
        if type(value) is not int or value != 0:
            raise ValueError
    for name in ("size", "matched_count", "filtered_count", "next_idx"):
        if name in root:
            value = metadata._integer(metadata._scalar(raw, root[name]), zero=True)
            if value != (0 if name == "next_idx" else 1):
                raise ValueError
    if "limit_reached" in root and metadata._scalar(raw, root["limit_reached"]) is not False:
        raise ValueError
    rows = metadata._array(raw, root["results"], 1)
    if len(rows) != 1:
        raise ValueError
    left, right = rows[0]
    row = metadata._object_spans(raw, left, right, _SELECTED)
    if not _SELECTED - {"q_origin_key"} <= row.keys():
        raise ValueError
    for name, expected_value in identity.items():
        value = metadata._scalar(raw, row[name])
        if type(value) is not type(expected_value) or value != expected_value:
            raise ValueError
    reference = metadata._scalar(raw, row["instruction-profile"])
    if type(reference) is not str or reference != instruction_profile_name:
        raise ValueError
    if "q_origin_key" in row:
        origin = metadata._scalar(raw, row["q_origin_key"])
        if not ((type(origin) is int and origin == identity["id"])
                or (type(origin) is str and origin == str(identity["id"]))):
            raise ValueError
    first, last = row["field"]
    with memoryview(raw)[first:last] as view:
        field.extend(view)
    slots = _slots(field)
    password_field_id = metadata._integer(metadata._scalar(field, slots["Password"]["id"]))
    totp = metadata._object_spans(raw, *row["totp-setting"], frozenset({"status", "shared-key"}))
    if metadata._scalar(raw, totp["status"]) != "disable":
        raise ValueError
    shared = totp["shared-key"]
    with memoryview(raw)[slice(*shared)] as token:
        if not hmac.compare_digest(token, b"null") and token[0] != 34:
            raise ValueError
    return left, right, row, password_field_id, shared


def consume_secret_instruction_build29_api_preservation(
    raw: bytearray, *, identity: Mapping[str, object], serial_digest: str,
    instruction_profile_name: str,
    credential_before: SecretInstructionBuild29CredentialWitness,
    credential_after: SecretInstructionBuild29CredentialWitness,
    totp_before: SecretApprovalBuild29TotpWitness, totp_after: SecretApprovalBuild29TotpWitness,
    witness_key: bytes | bytearray,
) -> SecretInstructionBuild29ApiPreservationWitness:
    """Consume one full fixed Web detail row and bracketed material evidence.

    Hash every row byte, replacing only the root Instruction value and direct
    TOTP shared-key render. No other configuration, computed permission, unknown
    field, credential slot or password render is excluded. Response whitespace
    and order remain significant; differences conservatively fail preservation.

    The producer must establish that this is an unprojected complete detail read,
    and independently qualify both exact Password and TOTP requests on the same
    subject/key/actor. This supports the existing targetless Web fixture scope
    with disabled, explicitly empty TOTP; null/masked CMDB values are never empty
    material evidence. No source completeness, ownership or authority is inferred.
    """
    field = bytearray()
    try:
        _key(witness_key, raw)
        left, right, row, password_field_id, shared = _qualify_web_detail(raw,
            identity=identity, serial_digest=serial_digest,
            instruction_profile_name=instruction_profile_name, field=field)
        secret_id = metadata._integer(identity["id"])
        _credential_bracket(credential_before, credential_after, secret_id=secret_id,
                            field_id=password_field_id, key=witness_key)
        _qualify_bracket(totp_before, totp_after, witness_key)
        if totp_before.explicit_empty is not True:
            raise ValueError
        replacements = sorted([(row["instruction-profile"], b'"instruction-reference-excluded"'),
                               (shared, b'"totp-semantic:' + totp_before.material_digest.encode("ascii") + b'"')])
        digest = hmac.new(witness_key, digestmod=hashlib.sha256)
        digest.update(_DOMAIN)
        digest.update(credential_before.material_digest.encode("ascii"))
        cursor = left
        for (first, last), replacement in replacements:
            if not cursor <= first < last <= right:
                raise ValueError
            with memoryview(raw)[cursor:first] as view:
                digest.update(view)
            digest.update(replacement)
            cursor = last
        with memoryview(raw)[cursor:right] as view:
            digest.update(view)
        return SecretInstructionBuild29ApiPreservationWitness(digest.hexdigest())
    except Exception:
        raise SecretInstructionBuild29ApiPreservationError() from None
    finally:
        try:
            _zeroize_mutable(field)
        finally:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)
