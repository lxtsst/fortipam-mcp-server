"""Private build-29 withdrawal ACK qualification without dispatch authority.

Source: the retained native DELETE /api/v2/internal/request-review/{id} ACK
qualified on 2026-10-08. Its vdom is the empty string, despite the root CMDB
read scope. Do not substitute the GET envelope or infer an absent Request.
An ACK does not establish final state, access effects, or replay permission.
"""

from dataclasses import asdict, dataclass
import json

from .secret_approval_build29_http_transport import _raw_members, _validate_ack_json
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, _json_value_end, _skip_json_space, _zeroize_mutable,
)
from .secret_request_approval_revoke_detail_contract import (
    SecretRequestApprovalRevokeDetailBinding, _digest, _reject_constant, _unique_members,
)

_UNAVAILABLE = "The fixed Launcher Request withdrawal acknowledgement is unavailable."
_CONTRACT = "secret-request-approval-revoke-build29-delete-ack-v1"
_ENVELOPE = {
    "status": "OK", "http_status": 200, "http_method": "DELETE",
    "vdom": "", "path": "secret", "name": "request-approval",
    "msg": "Successfully deleted approval entry",
}


class SecretRequestApprovalRevokeAckContractError(ValueError):
    """Stable refusal without response values or private identities."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestApprovalRevokeAckWitness:
    """Private digests only; neither readback nor a dispatch permit."""

    private_binding_digest: str
    private_native_ack_digest: str


def qualify_secret_request_approval_revoke_ack(
    native_json: bytes | bytearray, *, http_status: int,
    binding: SecretRequestApprovalRevokeDetailBinding, authenticated_reviewer: str,
) -> SecretRequestApprovalRevokeAckWitness:
    """Qualify the exact bounded native ACK and same-session caller binding.

    The ACK has no Request ID or device serial. The trusted transport must tie
    these bytes, HTTP status and actual authenticated reviewer to the bound
    original dispatch. This pure function cannot authenticate that provenance.
    Unknown keys and non-scalar values are refused before value decoding;
    native message text never appears in the witness or exception.
    """
    try:
        if (type(http_status) is not int or http_status != 200
                or type(binding) is not SecretRequestApprovalRevokeDetailBinding
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
            seen: set[str] = set()
            for key, _, left, _, _ in _raw_members(raw, start, end):
                if key in seen or key not in _ENVELOPE or raw[left] in (91, 123):
                    raise ValueError
                seen.add(key)
            if seen != set(_ENVELOPE):
                raise ValueError
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_members,
                                 parse_constant=_reject_constant)
            if any(type(payload[key]) is not type(value) or payload[key] != value
                   for key, value in _ENVELOPE.items()):
                raise ValueError
            return SecretRequestApprovalRevokeAckWitness(
                private_binding_digest=_digest({"contract": _CONTRACT, "binding": asdict(binding)}),
                private_native_ack_digest=_digest(payload),
            )
        finally:
            _zeroize_mutable(raw)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError,
            RuntimeError, IndexError):
        raise SecretRequestApprovalRevokeAckContractError(_UNAVAILABLE) from None
