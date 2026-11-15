"""Verify retained original-creation provenance inside the protected runtime.

Accepts the existing same-invocation v1 signed record, never a current Profile
as a replacement. The runtime must independently resolve the original signing
key, create outcome and expected parent/actor bindings from protected sources.
A valid HMAC cannot establish that a caller-supplied key is trustworthy. This
pure check performs no I/O, grants no authority and does not revive consumed
claims or establish present device state, approval window or session freshness.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import hmac
import json
import math
from typing import Any

from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, _skip_json_space, _json_value_end, _zeroize_mutable,
)
from .secret_approval_build29_http_transport import _raw_members, _validate_ack_json
from .secret_request_collection_http_transport import SecretRequestCollectionRecord
from .secret_request_approval_revoke_detail_contract import (
    SecretRequestApprovalRevokeDetailBinding,
    SecretRequestApprovalRevokeRelationWitness,
    qualify_secret_request_approval_revoke_secret_profile_relation,
    _reject_raw_duplicates,
)

_CONTRACT = "bp008-same-invocation-original-request-relation-v1"
_UNAVAILABLE = "Original Request creation continuity is unavailable."
_PAYLOAD_KEYS = frozenset({
    "contract", "binding", "created_record", "precreate_parent", "parent_binding",
    "authenticated_requester_digest", "authenticated_transport_digest", "relation_witness",
    "linux_parent_binding", "create_started_at", "create_finished_at",
})


class SecretRequestApprovalRevokeContinuityError(ValueError):
    """Non-disclosing failure of original provenance qualification."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestApprovalRevokeContinuityExpected:
    """Independent protected creation records, never MCP caller arguments.

    ``parent_binding_json`` is the original approval-and-observe binding;
    requester/transport digests identify the authenticated *create* invocation.
    Never copy expectations out of the signed record to claim independence.
    Construction alone establishes neither provenance nor execution authority.
    """

    binding: SecretRequestApprovalRevokeDetailBinding
    created_record: SecretRequestCollectionRecord
    parent_binding_json: bytes
    requester_digest: str
    transport_digest: str
    environment_ref: str
    scope_ref: str
    secret_name: str
    folder_path: str
    folder_id: int
    template_name: str
    target_name: str


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestApprovalRevokeContinuityWitness:
    """Private immutable evidence; never an authorization or dispatch permit."""

    private_continuity_digest: str
    relation: SecretRequestApprovalRevokeRelationWitness


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError


def _decode(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_RESPONSE_BYTES:
        raise ValueError
    buffer = bytearray(raw)
    try:
        start = _skip_json_space(buffer, 0)
        end = _json_value_end(buffer, start)
        if _skip_json_space(buffer, end) != len(buffer):
            raise ValueError
        _validate_ack_json(buffer, start, end)
        _reject_raw_duplicates(buffer, start, end)
        _reject_material_values(buffer, start, end)
        value = json.loads(buffer, object_pairs_hook=_members, parse_constant=_constant)
    finally:
        _zeroize_mutable(buffer)
    if type(value) is not dict:
        raise ValueError
    return value


def _reject_material_values(raw: bytearray, start: int, end: int) -> None:
    """Reject material before decoding values, retaining only null/empty fields."""
    if raw[start] == 123:
        for name, _, left, right, _ in _raw_members(raw, start, end):
            if name in {"field", "keyinfo", "shared-key"}:
                empty_field = (name == "field" and raw[left] == 91
                               and _skip_json_space(raw, left + 1) == right - 1)
                if raw[left:right] != b"null" and not empty_field:
                    raise ValueError
            _reject_material_values(raw, left, right)
    elif raw[start] == 91:
        cursor = _skip_json_space(raw, start + 1)
        while cursor < end - 1:
            right = _json_value_end(raw, cursor)
            _reject_material_values(raw, cursor, right)
            cursor = _skip_json_space(raw, right)
            if cursor < end - 1:
                cursor = _skip_json_space(raw, cursor + 1)


def _same(left: object, right: object) -> bool:
    # Canonical JSON also distinguishes boolean/integer and integer/float joins.
    return _canonical(left) == _canonical(right)


def _match(row: dict[str, Any], expected: dict[str, Any]) -> None:
    if type(row) is not dict or any(key not in row or not _same(row[key], value)
                                    for key, value in expected.items()):
        raise ValueError


def _digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _time(value: object) -> float:
    if (not isinstance(value, (int, float)) or type(value) not in (int, float)
            or not math.isfinite(value) or value <= 0):
        raise ValueError
    return float(value)


def qualify_secret_request_approval_revoke_continuity(
    signed_record_json: bytes, *, verification_key: bytes,
    expected: SecretRequestApprovalRevokeContinuityExpected,
) -> SecretRequestApprovalRevokeContinuityWitness:
    """Recheck signed pre-create sources, exact outcome and all original joins.

    Historical device Dates are compared with the historical observation, never
    with today's clock. A separate current inspection remains mandatory. Keys
    are borrowed only for this call and are not retained in the returned witness.
    The caller owns protected key acquisition, lifetime and source trust.
    """
    try:
        if (type(expected) is not SecretRequestApprovalRevokeContinuityExpected
                or type(verification_key) is not bytes or len(verification_key) != 32
                or type(expected.binding) is not SecretRequestApprovalRevokeDetailBinding
                or type(expected.created_record) is not SecretRequestCollectionRecord
                or not _digest(expected.requester_digest) or not _digest(expected.transport_digest)
                or type(expected.folder_id) is not int or not 0 < expected.folder_id <= 2_147_483_647):
            raise ValueError
        for value in (expected.environment_ref, expected.scope_ref, expected.secret_name,
                      expected.folder_path, expected.template_name, expected.target_name):
            if type(value) is not str or not value or len(value) > 1024 or any(ord(c) < 32 for c in value):
                raise ValueError
        record = _decode(signed_record_json)
        if set(record) != {"payload", "hmac_sha256"} or not _digest(record["hmac_sha256"]):
            raise ValueError
        payload = record["payload"]
        encoded = _canonical(payload)
        signature = hmac.new(verification_key, encoded, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, record["hmac_sha256"]):
            raise ValueError
        if type(payload) is not dict or set(payload) != _PAYLOAD_KEYS or payload["contract"] != _CONTRACT:
            raise ValueError
        binding = expected.binding
        # Reconstruct to validate even a wrongly manufactured dataclass instance.
        SecretRequestApprovalRevokeDetailBinding(**asdict(binding))
        if (not _same(payload["binding"], asdict(binding))
                or not _same(payload["created_record"], asdict(expected.created_record))):
            raise ValueError
        _match(payload["created_record"], {"request_id": binding.request_id,
               "secret_id": binding.secret_id, "request_type": "launcher"})
        creation_time = expected.created_record.creation_time
        if (type(creation_time) not in (str, int) or isinstance(creation_time, bool)
                or (type(creation_time) is int and creation_time <= 0)
                or (type(creation_time) is str and not creation_time)):
            raise ValueError
        if (payload["authenticated_requester_digest"] != expected.requester_digest
                or payload["authenticated_transport_digest"] != expected.transport_digest):
            raise ValueError
        parent_binding = _decode(expected.parent_binding_json)
        if not _same(payload["parent_binding"], parent_binding):
            raise ValueError
        scope = {"secret_id": binding.secret_id, "secret_name": expected.secret_name,
                 "folder_path": expected.folder_path, "environment_ref": expected.environment_ref,
                 "scope_ref": expected.scope_ref}
        _match(parent_binding, {**scope, "requester_digest": expected.requester_digest,
                                "approval_profile_name": binding.approval_profile_name})
        parent = payload["precreate_parent"]
        if type(parent) is not dict or set(parent) != {"selected", "sources", "device_dates", "observed_at"}:
            raise ValueError
        linux = {"folder_id": expected.folder_id, "template_name": expected.template_name,
                 "target_name": expected.target_name}
        if not _same(payload["linux_parent_binding"], linux):
            raise ValueError
        _match(parent["selected"], {**scope, **linux, "requester": binding.requester,
               "approval_profile_name": binding.approval_profile_name,
               "original_reviewer": binding.original_reviewer, "source_serial": binding.source_serial})
        observed = _time(parent["observed_at"])
        started, finished = _time(payload["create_started_at"]), _time(payload["create_finished_at"])
        if not observed <= started <= finished <= observed + 60:
            raise ValueError
        sources, dates = parent["sources"], parent["device_dates"]
        if type(sources) is not dict or set(sources) != {"role", "secret", "profile"}:
            raise ValueError
        if type(dates) is not dict or set(dates) != set(sources):
            raise ValueError
        # Native Secret route may omit Date; role and Profile may not.
        for name in sources:
            if dates[name] is None and name == "secret":
                continue
            if type(dates[name]) is not str:
                raise ValueError
            date = datetime.fromisoformat(dates[name])
            if date.tzinfo is None or abs(date.timestamp() - observed) > 105:
                raise ValueError
        # The original collector bounded its reads to 60s and Date skew to 45s.
        role = sources["role"]
        _match(role, {"version": "v7.0.0", "build": 29, "http_method": "GET",
                     "http_status": 200, "status": "success", "serial": binding.source_serial,
                     "path": "system", "name": "admin"})
        if set(role) != {"version", "build", "http_method", "http_status", "status", "serial",
                         "path", "name", "results", "vdom", "mkey", "revision"}:
            raise ValueError
        _match(role, {"vdom": "root", "mkey": binding.original_reviewer})
        revision = role["revision"]
        if type(revision) is not str or not revision or len(revision) > 1024:
            raise ValueError
        role_rows = role["results"]
        if type(role_rows) is not list or len(role_rows) != 1 or type(role_rows[0]) is not dict:
            raise ValueError
        role_row = role_rows[0]
        if set(role_row) != {"name", "q_origin_key", "accprofile", "status", "remote-auth", "wildcard"}:
            raise ValueError
        _match(role_row, {"name": binding.original_reviewer, "accprofile": "super_admin",
                         "status": "enable", "remote-auth": "disable", "wildcard": "disable",
                         "q_origin_key": binding.original_reviewer})
        relation = qualify_secret_request_approval_revoke_secret_profile_relation(
            _canonical(sources["secret"]), _canonical(sources["profile"]), binding=binding,
            authenticated_reviewer=binding.original_reviewer,
        )
        _match(sources["secret"]["results"][0], {"name": expected.secret_name,
               "folder": expected.folder_id, "template": expected.template_name,
               "target": expected.target_name, "need-approval-job": "disable"})
        if not _same(payload["relation_witness"], asdict(relation)):
            raise ValueError
        return SecretRequestApprovalRevokeContinuityWitness(hashlib.sha256(encoded).hexdigest(), relation)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError, RecursionError, RuntimeError):
        raise SecretRequestApprovalRevokeContinuityError(_UNAVAILABLE) from None


def qualify_secret_request_approval_revoke_with_invocation(
    signed_record_json: bytes, *, verification_key: bytes,
    expected: SecretRequestApprovalRevokeContinuityExpected,
    invocation: object,
) -> SecretRequestApprovalRevokeContinuityWitness:
    """Join independently loaded create invocation evidence before provenance.

    The protected caller must load invocation evidence using its independently
    configured witness store and verify the original create claim is terminal
    BOUND. Neither a constructed dataclass nor these checks authenticates a file
    source. This function cannot authorize withdrawal or revive a consumed claim.
    The producer must reuse the actual invocation timestamps in its signed parent
    continuity record; a separately estimated timestamp is not the same event.
    """
    from .secret_request_create_invocation_witness import SecretRequestCreateInvocationWitness

    try:
        if (type(invocation) is not SecretRequestCreateInvocationWitness
                or type(expected) is not SecretRequestApprovalRevokeContinuityExpected
                or invocation.requester_digest != expected.requester_digest
                or invocation.transport_digest != expected.transport_digest
                or invocation.fortipam_requester != expected.binding.requester
                or invocation.environment_ref != expected.environment_ref
                or invocation.scope_ref != expected.scope_ref
                or not _same(asdict(invocation.created_record), asdict(expected.created_record))):
            raise ValueError
        payload = _decode(signed_record_json)["payload"]
        if (not _same(payload["create_started_at"], invocation.create_started_at)
                or not _same(payload["create_finished_at"], invocation.create_finished_at)):
            raise ValueError
        return qualify_secret_request_approval_revoke_continuity(
            signed_record_json, verification_key=verification_key, expected=expected,
        )
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError, RecursionError):
        raise SecretRequestApprovalRevokeContinuityError(_UNAVAILABLE) from None
