"""Private build29 complete Policy definition; no association or authority.

The fixed field classification follows the qualified native Policy contract.
Only locators, header scalars and integers are decoded. Other Policy strings
remain opaque tokens, with three compiled control enums classified separately.
This read cannot establish ownership, inheritance, active-session absence or
permission to assign a Policy. Frozen Windows/Folder contracts stay unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _zeroize_mutable
from .target_lifecycle_dependencies import _envelope, _one, _spans
from .target_preservation_contract import _digest, _token_digest

CONTRACT = "fortipam-build29-policy-assignment-definition-v1"
_ERROR = "The private Policy definition is unavailable."
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_NAME = re.compile(r'[^/\\\x00-\x1f\x7f]{1,64}\Z')
_FIELDS = frozenset({
    "name", "password-changer", "password-heartbeat", "checkout", "recording", "need-approval",
    "need-approval-job", "av-scan", "dlp-status", "proxy", "ssh-filter", "ssh-algorithm", "winappfilter",
    "rdp-remote-app", "rdp-remote-app-profile", "rdp-remote-app-owner-exempt", "rdp-security-level",
    "rdp-auto-totp", "rdp-restricted-admin-mode", "block-clipboard", "cert-expiry-log",
    "pwd-chg-sch-frequency", "pwd-chg-sch-interval", "pwd-chg-sch-month-type", "pwd-chg-sch-month-day",
    "pwd-chg-sch-week-day", "pwd-chg-sch-start-date", "heartbeat-interval", "heartbeat-start-time",
    "checkout-duration", "force-checkout-idle-time", "checkin-pwd-change", "checkout-duration-renew",
    "checkout-renew-times", "tunnel-encryption", "secret-auth", "secret-auth-server", "secret-auth-duration",
    "secret-auth-owner-exempt", "bypass-approval", "approval-profile", "ssh-filter-profile",
    "bypass-ssh-filter-for-owner", "winappfilter-profile", "dlp-sensor", "av-profile",
    "pwd-chg-secret-edit", "heartbeat-secret-edit", "rdp-event-filter", "rdp-event-filter-profile",
    "credential-expire-notification", "credential-expiry-after", "last-credential-change-date", "rdp-nla-kerberos",
})
_META = frozenset({"q_origin_key", "q_ref", "q_static", "q_no_edit", "q_no_rename", "q_global_entry",
    "q_type", "q_path", "q_name", "q_mkey_type"})
_INTEGERS = frozenset({"pwd-chg-sch-interval", "heartbeat-interval", "checkout-duration",
    "force-checkout-idle-time", "checkout-renew-times", "secret-auth-duration", "credential-expiry-after"})
_BOOLEAN_META = frozenset({"q_static", "q_no_edit", "q_no_rename", "q_global_entry"})
_CONTROLS = ("recording", "block-clipboard", "rdp-event-filter")
_OPTIONS = ("disable", "enable", "not-set")
_RELATIONS = frozenset({"secret-auth-server", "approval-profile", "ssh-filter-profile", "winappfilter-profile",
    "dlp-sensor", "av-profile", "rdp-event-filter-profile", "rdp-remote-app-profile"})


class PolicyAssignmentDefinitionError(ValueError):
    """Fixed denial without a native field value or upstream exception."""


def _equals(content: bytearray, span: tuple[int, int], value: bytes) -> bool:
    with memoryview(content)[slice(*span)] as token:
        return token == value


def _integer(content: bytearray, span: tuple[int, int]) -> int:
    left, right = span
    if not 0 < right - left <= 10:
        raise ValueError
    with memoryview(content)[left:right] as token:
        if any(byte not in b"0123456789" for byte in token):
            raise ValueError
        value = int(token)
    if not 0 <= value <= 2147483647:
        raise ValueError
    return value


@dataclass(frozen=True, slots=True, repr=False)
class PolicyAssignmentDefinition(_OpaqueC3Object):
    """Private full-state fingerprints are observations, never original custody."""
    policy_name_digest: str
    configuration_digest: str
    state_digest: str
    controls: tuple[str, str, str]
    reference_count: int
    configured_relation_count: int

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT, classified_policy_field_count=len(_FIELDS),
            complete_classified_policy_definition_bound=True,
            session_control_values=dict(zip(_CONTROLS, self.controls, strict=True)),
            definition_references_present=self.reference_count > 0,
            configured_relation_count=self.configured_relation_count,
            policy_values_or_locators_returned=False, full_policy_semantics_reviewed=False,
            ownership_qualified=False, secret_inheritance_qualified=False, assignment_authorized=False)


def consume_policy_assignment_definition(content: bytearray, *, policy_name: str,
        serial_digest: str) -> PolicyAssignmentDefinition:
    """Bind every classified configuration token and fixed native metadata.

    A distinct configuration fingerprint detects changes outside the three
    control fields while allowing callers to compare native reference-count
    changes separately. Unknown/container fields reject before scalar decoding.
    The owned raw buffer clears on every exit, including interruption.
    """
    try:
        if (type(policy_name) is not str or _NAME.fullmatch(policy_name) is None
                or type(serial_digest) is not str or _HEX.fullmatch(serial_digest) is None):
            raise ValueError
        fields = _spans(content)
        row = _one(content, _envelope(content, path="secret", name="policy", serial_digest=serial_digest))
        members = _object_spans(content, *row)
        if set(members) != _FIELDS | _META or "mkey" not in fields:
            raise ValueError
        # These are the only classified source locator strings, not values.
        for span in (fields["mkey"], members["name"], members["q_origin_key"]):
            if content[span[0]] != 34 or metadata._scalar(content, span) != policy_name:
                raise ValueError
        for name in _FIELDS - _INTEGERS:
            left, right = members[name]
            if content[left] != 34 or right - left > 8192:
                raise ValueError
        for name in _INTEGERS | {"q_ref", "q_type"}:
            _integer(content, members[name])
        for name in _BOOLEAN_META:
            if not any(_equals(content, members[name], value) for value in (b"true", b"false")):
                raise ValueError
        for name, expected in {"q_path": b'"secret"', "q_name": b'"policy"', "q_mkey_type": b'"string"'}.items():
            if not _equals(content, members[name], expected):
                raise ValueError
        controls = []
        for name in _CONTROLS:
            matches = [value for value in _OPTIONS if _equals(content, members[name], ('"' + value + '"').encode())]
            if len(matches) != 1:
                raise ValueError
            controls.append(matches[0])
        tokens = {name: _token_digest(content, members[name]) for name in _FIELDS}
        return PolicyAssignmentDefinition(_digest(policy_name), _digest((CONTRACT, tokens)),
            _digest((CONTRACT, serial_digest, tokens, {name: _token_digest(content, members[name]) for name in _META})),
            (controls[0], controls[1], controls[2]), _integer(content, members["q_ref"]),
            sum(not _equals(content, members[name], b'""') for name in _RELATIONS))
    except Exception:
        raise PolicyAssignmentDefinitionError(_ERROR) from None
    finally:
        if type(content) is bytearray:
            _zeroize_mutable(content)
