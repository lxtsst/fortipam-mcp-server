"""Private complete owned-JWT state candidate, without ownership or authority.

Only a producer with an original success ACK may fetch these exact-key bodies.
Native created-row metadata and success/readback semantics remain unqualified.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from typing import cast

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as parser
from .jwt_manual_key_contract import DEFAULT_FIELDS, JwtManualPublicKey, _digest, _require_digest
from .jwt_manual_key_preflight import JwtManualKeyPreflight, _collection, _top
from .jwt_manual_key_request_contract import JwtManualCreateRequest
from .local_user_reset_projection import _object_spans as _all_spans
from .secret_metadata_http_transport import _zeroize_mutable
from .target_lifecycle_dependencies import _envelope, _one

_CONTRACT = "fortipam-build29-manual-jwt-owned-state-private-v1"
_ERROR = "The private owned JWT-key state is unavailable."
_META = frozenset({"q_global_entry", "q_mkey_type", "q_name", "q_no_edit", "q_no_rename",
    "q_origin_key", "q_path", "q_ref", "q_static", "q_type"})


class JwtManualKeyOwnedStateError(RuntimeError):
    """Non-disclosing refusal; never an adoption or deletion permission."""


@dataclass(frozen=True, slots=True, repr=False)
class JwtManualKeyOwnedState(_OpaqueC3Object):
    request_digest: str
    full_row_hmac: str
    api_users_digest: str
    key_namespace_digest: str
    postcondition_digest: str


def expected_jwt_manual_key_created_state(request: JwtManualCreateRequest, baseline: JwtManualKeyPreflight) -> str:
    """Bind the planned semantic postcondition; no device or body access.

    Closed original request metadata can be used for independent preservation;
    trusted original custody must bind it before any owned-key read.
    """
    try:
        if (type(request) is not JwtManualCreateRequest or type(baseline) is not JwtManualKeyPreflight
                or request._request_digest() != request.digest
                or baseline.name_digest != hashlib.sha256(request._name.encode()).hexdigest()
                or baseline.serial_digest != request.serial_digest or baseline.schema_digest != request.schema_digest
                or baseline.defaults_digest != request.defaults_digest):
            raise ValueError
        for value in (request.digest, baseline.api_users_digest, baseline.state_digest):
            _require_digest(value)
        return _digest({"contract": _CONTRACT, "request": request.digest, "preflight": baseline.state_digest,
            "api_users": baseline.api_users_digest, "complete_pristine_owned_key": True})
    except Exception:
        raise JwtManualKeyOwnedStateError(_ERROR) from None


def _row(raw: bytearray, request: JwtManualCreateRequest) -> dict[str, object]:
    span = _envelope(raw, path="secret", name="jwt-key", serial_digest=request.serial_digest)
    top = _top(raw)
    if ("schema_errors" in top or parser._scalar(raw, top["mkey"]) != request._name):
        raise ValueError
    fields = _all_spans(raw, *_one(raw, span))
    # Classify the complete row before decoding any values; new fields refuse.
    if set(fields) != DEFAULT_FIELDS | _META:
        raise ValueError
    key_spans = parser._array(raw, fields["key"], 1)
    if len(key_spans) != 1 or not {"key-name"} <= _all_spans(raw, *key_spans[0]).keys() <= {"key-name", "q_origin_key"}:
        raise ValueError
    if parser._array(raw, fields["claim"], 1):
        raise ValueError
    row = {key: json.loads(raw[slice(*value)]) for key, value in fields.items()}
    for key, value in {"name": request._name, "type": "manually", "jwks-url": "", "oidc-discovery-url": "",
            "ca": "", "check-interval": 24, "q_origin_key": request._name, "q_path": "secret", "q_name": "jwt-key",
            "q_mkey_type": "string", "q_ref": 0, "q_static": False, "q_no_edit": False,
            "q_no_rename": False, "q_global_entry": False}.items():
        if type(row[key]) is not type(value) or row[key] != value:
            raise ValueError
    if type(row["q_type"]) is not int or not 0 <= row["q_type"] < 2 ** 31:
        raise ValueError
    if type(row["claim"]) is not list or row["claim"]:
        raise ValueError
    for key in ("last-check-time", "last-update-time"):
        parser._text(row[key], empty=True, maximum=128)
    keys = row["key"]
    if (type(keys) is not list or len(keys) != 1 or type(keys[0]) is not dict
            or not {"key-name"} <= keys[0].keys() <= {"key-name", "q_origin_key"}):
        raise ValueError
    key = keys[0]["key-name"]
    if type(key) is not str:
        raise ValueError
    JwtManualPublicKey(key.encode("ascii"))
    if "q_origin_key" in keys[0] and keys[0]["q_origin_key"] != key:
        raise ValueError
    return row


def consume_jwt_manual_key_owned_state(
    detail_before: bytearray, keys: bytearray, users: bytearray, detail_after: bytearray, *,
    request: JwtManualCreateRequest, baseline: JwtManualKeyPreflight, witness_key: bytes,
    expected_full_row_hmac: str | None = None,
    require_original_body_digest: bool = False,
) -> JwtManualKeyOwnedState:
    """Bracket complete rows and selected relationships; always erase inputs.

    Initial capture compares the actual public key with the live original body.
    Independent preservation uses only the original sealed row HMAC and closed
    request metadata, never reloads material or promotes the original result.
    """
    buffers = (detail_before, keys, users, detail_after)
    try:
        postcondition = expected_jwt_manual_key_created_state(request, baseline)
        if type(witness_key) is not bytes or len(witness_key) != 32:
            raise ValueError
        if type(require_original_body_digest) is not bool:
            raise ValueError
        if expected_full_row_hmac is None and not require_original_body_digest:
            request.validate()
        elif expected_full_row_hmac is not None:
            _require_digest(expected_full_row_hmac)
        first, last = _row(detail_before, request), _row(detail_after, request)
        if first != last:
            raise ValueError
        encoded = json.dumps(first, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        row_hmac = hmac.new(witness_key, _CONTRACT.encode() + b"\x00" + request.digest.encode() + b"\x00" + encoded,
                           hashlib.sha256).hexdigest()
        if expected_full_row_hmac is not None:
            if not hmac.compare_digest(row_hmac, expected_full_row_hmac):
                raise ValueError
        elif require_original_body_digest:
            # Reconstruct only the seven fixed native wire fields. The original
            # request commits to these bytes, so recovery needs no live body or
            # reload of retained material when the original state was not sealed.
            members = cast(list[dict[str, object]], first["key"])
            wire = {key: first[key] for key in ("name", "type", "key", "jwks-url", "check-interval", "ca", "claim")}
            wire["key"] = [{"key-name": members[0]["key-name"]}]
            compiled = bytearray(json.dumps(wire, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode())
            try:
                if hashlib.sha256(compiled).hexdigest() != request.body_digest:
                    raise ValueError
            finally:
                _zeroize_mutable(compiled)
        else:
            with request.borrow_body() as view:
                expected = json.loads(view.tobytes())
            for key, value in expected.items():
                if key == "key":
                    actual = cast(list[dict[str, object]], first["key"])
                    if actual[0]["key-name"] != value[0]["key-name"]:
                        raise ValueError
                elif type(first[key]) is not type(value) or first[key] != value:
                    raise ValueError
        key_rows, key_meta = _collection(keys, "jwt-key", request.serial_digest)
        user_rows, _ = _collection(users, "api-user", request.serial_digest)
        if key_rows != [{"name": request._name, "type": "manually"}]:
            raise ValueError
        users_digest = _digest(user_rows)
        if (users_digest != baseline.api_users_digest or not user_rows
                or any(row["type"] == "jwt" or row["jwt-key"] != "" for row in user_rows)):
            raise ValueError
        return JwtManualKeyOwnedState(request.digest, row_hmac, users_digest,
            _digest({"rows": key_rows, "metadata": key_meta}), postcondition)
    except Exception:
        raise JwtManualKeyOwnedStateError(_ERROR) from None
    finally:
        for raw in buffers:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)


__all__ = ["JwtManualKeyOwnedStateError", "JwtManualKeyOwnedState", "expected_jwt_manual_key_created_state",
           "consume_jwt_manual_key_owned_state"]
