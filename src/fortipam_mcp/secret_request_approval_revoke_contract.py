"""Build-29 frontend approval withdrawal primitives, with no dispatch authority.

Source: checkout_main_current.js / job_main_current.js, SHA256
0c2bf35bb5cde1a5154012d6bf2f529d8d59e782a35aebe0bd29976ca9da434f.
Module 50902 offsets 364398/365088 supplies the DELETE serializer/URL;
43916 offsets 57196/82934/90392 and 86764 offset 240551 supply eligibility.
Offsets are zero-based characters in the one-line asset.

Eligibility consumes only an explicit name/status tier projection, not a native
CMDB detail or a complete frontend model. It proves neither product permission,
an active access window, native readback, exact Secret/Profile binding, nor
execution authorization. Those admissions require separate qualification.

The native tier qualifier additionally pins the independently observed shared
Job/Launcher tier grammar: name/q_origin_key/status/comments are strings;
update-time has observed string and integer representations.
Its private witness covers only tiers, not complete Launcher admission.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json

from .secret_metadata_http_transport import MAX_RESPONSE_BYTES
from .secret_request_http_transport import _v70_launcher_availability

_UNAVAILABLE = "The fixed Launcher Request approval withdrawal is unavailable."
_REVIEW_PATH = "/api/v2/internal/request-review"
_TIERS = frozenset({"tier1", "tier2", "tier3"})
_STATUSES = frozenset({"approved", "denied", "pending"})
_NATIVE_TIER_MEMBERS = frozenset({"name", "q_origin_key", "status", "comments", "update-time"})
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


class SecretRequestApprovalRevokeContractError(ValueError):
    """Stable refusal without protected identifiers or model contents."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestApprovalRevokeNativeTierWitness:
    """Private preservation digest only; never public output or an authority.

    It does not bind Request/Secret/Profile, device identity, permissions,
    access window, native DELETE acknowledgement, or an execution intent.
    """

    private_digest: str


def qualify_secret_request_approval_revoke_native_tiers(
    tier_approvals: object, *, requester: str, authenticated_reviewer: str,
) -> SecretRequestApprovalRevokeNativeTierWitness:
    """Qualify the shared build-29 tier grammar from duplicate-free native JSON.

    The caller must parse JSON with duplicate-key rejection before selecting
    these tiers. Comments and update-time remain bounded opaque values; no
    date or business semantics are inferred. The full native read/envelope and
    original product reviewer binding must be qualified independently. Opaque
    text uses the existing Request reader's response budget; that reader must
    still enforce MAX_RESPONSE_BYTES on the complete response, not each field.
    """
    if (not _identity(requester) or not _identity(authenticated_reviewer)
            or requester == authenticated_reviewer
            or type(tier_approvals) is not dict or set(tier_approvals) != _TIERS):
        raise SecretRequestApprovalRevokeContractError(_UNAVAILABLE)
    snapshot: dict[str, list[dict[str, str | int]]] = {}
    for tier in ("tier1", "tier2", "tier3"):
        entries = tier_approvals[tier]
        if type(entries) is not list or len(entries) != (1 if tier == "tier1" else 0):
            raise SecretRequestApprovalRevokeContractError(_UNAVAILABLE)
        snapshot[tier] = []
        for entry in entries:
            if type(entry) is not dict or set(entry) != _NATIVE_TIER_MEMBERS:
                raise SecretRequestApprovalRevokeContractError(_UNAVAILABLE)
            if (not _identity(entry["name"]) or not _identity(entry["q_origin_key"])
                    or entry["name"] != authenticated_reviewer
                    or entry["q_origin_key"] != authenticated_reviewer
                    or type(entry["status"]) is not str or entry["status"] != "approved"
                    or not _opaque_native_text(entry["comments"])
                    or not _opaque_native_update_time(entry["update-time"])):
                raise SecretRequestApprovalRevokeContractError(_UNAVAILABLE)
            snapshot[tier].append(dict(entry))
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    return SecretRequestApprovalRevokeNativeTierWitness(hashlib.sha256(canonical).hexdigest())


def _opaque_native_text(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return len(value.encode("utf-8")) <= MAX_RESPONSE_BYTES
    except UnicodeError:
        return False


def _opaque_native_update_time(value: object) -> bool:
    if type(value) is int:
        # Preserve JSON/JS safe integers without assigning timestamp semantics.
        return -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER
    return _opaque_native_text(value)


def secret_request_approval_revoke_launcher_window_available(
    window_fields: object, *, server_time: datetime | None,
) -> bool:
    """Check only a source-pinned Launcher window, never approval or authority.

    Module 86764 offsets 237389/237899 delegates native times to module 72531:
    converter offset 1885086 defaults to Seconds and SToMs=1000 at 1880214.
    The native integer seconds are adapted UTC->Shanghai before reusing the
    accepted string-window parser, device Date comparison and five-minute
    freshness rule. Original private values must remain independently pinned.
    Pending approval cannot be authorized by a true window predicate; the
    caller must separately qualify approved state, identities, Profile and
    execution authority. The caller supplies a qualified device Date.
    """
    if (type(window_fields) is not dict
            or set(window_fields) != {"start-time", "expiration-time", "timezone"}
            or type(window_fields["timezone"]) is not str
            or window_fields["timezone"] != "Asia/Shanghai"
            or not isinstance(server_time, datetime) or server_time.tzinfo is None):
        return False
    start = _native_launcher_time_text(window_fields["start-time"])
    end = _native_launcher_time_text(window_fields["expiration-time"])
    if start is None or end is None:
        return False
    try:
        if server_time.utcoffset() is None:
            return False
        return _v70_launcher_availability({
            "start-time": start, "expiration-time": end, "timezone": "Asia/Shanghai",
        }, server_time) == "available"
    except (TypeError, ValueError, OverflowError, OSError):
        return False


def _native_launcher_time_text(value: object) -> str | None:
    if type(value) is str:
        return value
    if type(value) is not int or not 0 < value <= _MAX_SAFE_INTEGER:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).astimezone(
            timezone(timedelta(hours=8)),
        ).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError, OSError):
        return None


def _request_id(value: int) -> int:
    if type(value) is not int or not 0 < value <= 2_147_483_647:
        raise SecretRequestApprovalRevokeContractError(_UNAVAILABLE)
    return value


def secret_request_approval_revoke_url(request_id: int) -> str:
    """Return the source-pinned internal URL; never a CMDB record deletion."""
    return f"{_REVIEW_PATH}/{_request_id(request_id)}"


def compile_secret_request_approval_revoke_body(
    *, request_id: int, tier: int = 1,
) -> dict[str, int]:
    """Serialize only two fields for the bounded tier-one profile.

    The frontend calls buildSecretRequestPayload(id, tier); all other optional
    properties are undefined and disappear during JSON serialization. A valid
    body alone does not admit a Launcher Request or authorize a DELETE.
    """
    identifier = _request_id(request_id)
    if type(tier) is not int or tier != 1:
        raise SecretRequestApprovalRevokeContractError(_UNAVAILABLE)
    return {"request-id": identifier, "tier": tier}


def single_reviewer_frontend_approval_revoke_eligible(
    tier_approvals: object, *, requester: str, authenticated_reviewer: str,
) -> bool:
    """Check a strict tier projection for one approval owned by this reviewer.

    Caller must independently qualify launcher type, native/model mapping,
    Request/Secret/Profile/actor bindings, timing, and the reviewer view.
    Unknown projection members are refused rather than silently discarded.
    """
    if not _identity(requester) or not _identity(authenticated_reviewer):
        return False
    if requester == authenticated_reviewer:
        return False
    if not isinstance(tier_approvals, Mapping) or set(tier_approvals) != _TIERS:
        return False
    for tier in _TIERS:
        entries = tier_approvals[tier]
        if not isinstance(entries, list):
            return False
        if len(entries) != (1 if tier == "tier1" else 0):
            return False
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != {"name", "status"}:
                return False
            name, status = entry["name"], entry["status"]
            if not _identity(name) or type(status) is not str or status not in _STATUSES:
                return False
            if name != authenticated_reviewer or status != "approved":
                return False
    return True


def _identity(value: object) -> bool:
    if type(value) is not str or not value or value != value.strip():
        return False
    try:
        return (len(value.encode("utf-8")) <= 255
                and not any(ord(char) < 32 or ord(char) == 127 for char in value))
    except UnicodeError:
        return False
