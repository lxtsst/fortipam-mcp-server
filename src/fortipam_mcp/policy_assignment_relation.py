"""Private build29 effective Policy read relation; no writer or admission.

The trusted producer supplies six fixed detail reads in a bounded authenticated
window. This projection binds the native Secret reference, the twelve-field
Folder relation and the complete Policy definition. It cannot establish full
Secret preservation, session effects, source provenance or assignment rights.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import uuid

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from .policy_assignment_definition import consume_policy_assignment_definition
from .secret_metadata_http_transport import _zeroize_mutable
from .target_lifecycle_dependencies import _one, _spans
from .target_preservation_contract import _digest, _token_digest

CONTRACT = "fortipam-build29-policy-assignment-read-relation-v1"
_ERROR = "The private effective Policy relation is unavailable."
_NAME = re.compile(r'[^/\\\x00-\x1f\x7f]{1,64}\Z')
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_SECRET = frozenset({"id", "name", "folder", "template", "target", "uuid", "policy",
    "recording", "http-service-status", "need-approval", "need-approval-job"})
_FOLDER = frozenset({"id", "name", "folder-type", "parent-folder", "inherit-policy",
    "inherit-permission", "inherit-folder-ztna", "secret-policy", "ztna-ems-tag",
    "ztna-tags-match-logic", "user-permission", "group-permission"})


class PolicyAssignmentRelationError(ValueError):
    """Fixed refusal without a selector, native field or upstream detail."""


@dataclass(frozen=True, slots=True, repr=False)
class PolicyAssignmentRelationBinding(_OpaqueC3Object):
    """Private source selectors, never a fixture or ownership declaration."""
    secret_id: int
    secret_name: str
    folder_id: int
    secret_uuid: str
    policy_name: str
    serial_digest: str

    def __post_init__(self) -> None:
        try:
            if any(type(value) is not int or not 0 < value <= 2147483647
                    for value in (self.secret_id, self.folder_id)):
                raise ValueError
            if any(type(value) is not str or _NAME.fullmatch(value) is None
                    for value in (self.secret_name, self.policy_name)):
                raise ValueError
            if (type(self.serial_digest) is not str or _HEX.fullmatch(self.serial_digest) is None
                    or type(self.secret_uuid) is not str or not uuid.UUID(self.secret_uuid).int
                    or str(uuid.UUID(self.secret_uuid)) != self.secret_uuid):
                raise ValueError
        except Exception:
            raise PolicyAssignmentRelationError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class PolicyAssignmentRelation(_OpaqueC3Object):
    secret_metadata_digest: str
    folder_configuration_digest: str
    policy_configuration_digest: str
    policy_state_digest: str
    relation_digest: str
    inherited: bool
    policy_controls: tuple[str, str, str]

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT, native_secret_folder_policy_match=True,
            bracketed_selected_metadata_stable=True, folder_policy_inheritance_enabled=self.inherited,
            classified_secret_metadata_fields=len(_SECRET), classified_folder_fields=len(_FOLDER),
            complete_policy_configuration_fields=54,
            session_control_definition=dict(zip(("recording", "block-clipboard", "rdp-event-filter"),
                self.policy_controls, strict=True)),
            complete_secret_preservation_qualified=False, activity_absence_qualified=False,
            access_or_launch_effect_qualified=False, source_provenance_qualified=False,
            ownership_qualified=False, assignment_authorized=False, locators_or_digests_returned=False)


def _detail(content: bytearray, table: str, serial: str) -> dict[str, tuple[int, int]]:
    fields = _spans(content)
    # These fixed projected Secret/Folder details use OK; the independent
    # complete Policy reader retains its qualified success envelope.
    _expect(content, fields, dict(version="v7.0.0", build=29, path="secret", name=table,
        http_method="GET", http_status=200, status="OK", vdom="root"))
    native_serial = metadata._text(metadata._scalar(content, fields["serial"]), maximum=128)
    if hashlib.sha256(native_serial.encode()).hexdigest() != serial or "action" in fields:
        raise ValueError
    if "error" in fields:
        _expect(content, fields, {"error": 0})
    span = _one(content, fields["results"])
    selected = _SECRET if table == "database" else _FOLDER
    row = metadata._object_spans(content, *span, selected)
    if not selected <= row.keys():
        raise ValueError
    # Detail identity is bound below. This is never collection exhaustion or
    # global visibility evidence, irrespective of optional pagination fields.
    if "limit_reached" in fields and metadata._scalar(content, fields["limit_reached"]) is not False:
        raise ValueError
    return row


def _expect(content: bytearray, fields: dict[str, tuple[int, int]], values: dict[str, object]) -> None:
    for key, expected in values.items():
        actual = metadata._scalar(content, fields[key])
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError


def _secret(content: bytearray, binding: PolicyAssignmentRelationBinding) -> str:
    row = _detail(content, "database", binding.serial_digest)
    _expect(content, row, dict(id=binding.secret_id, name=binding.secret_name, folder=binding.folder_id,
        template="Web Account", target="", uuid=binding.secret_uuid, policy=binding.policy_name))
    return _digest({name: _token_digest(content, row[name]) for name in _SECRET})


def _folder(content: bytearray, binding: PolicyAssignmentRelationBinding) -> tuple[str, bool]:
    row = _detail(content, "folder", binding.serial_digest)
    _expect(content, row, {"id": binding.folder_id, "secret-policy": binding.policy_name})
    inherited = metadata._scalar(content, row["inherit-policy"])
    if type(inherited) is not str or inherited not in {"enable", "disable"}:
        raise ValueError
    return _digest({name: _token_digest(content, row[name]) for name in _FOLDER}), inherited == "enable"


def consume_policy_assignment_relation(*, binding: PolicyAssignmentRelationBinding,
        secret_before: bytearray, folder_before: bytearray, policy_before: bytearray,
        policy_after: bytearray, folder_after: bytearray, secret_after: bytearray) -> PolicyAssignmentRelation:
    """Consume six private responses; only selected nonmaterial tokens survive.

    Unknown Secret values are skipped as bytes and are deliberately outside this
    selected metadata contract. In particular, this is not a credential/TOTP or
    full Secret preservation witness. Every owned buffer clears on every exit.
    The producer, rather than this pure join, must establish order and freshness.
    """
    buffers = (secret_before, folder_before, policy_before, policy_after, folder_after, secret_after)
    try:
        if (type(binding) is not PolicyAssignmentRelationBinding
                or any(type(content) is not bytearray for content in buffers)
                or len({id(content) for content in buffers}) != len(buffers)):
            raise ValueError
        binding.__post_init__()
        secret = _secret(secret_before, binding)
        folder, inherited = _folder(folder_before, binding)
        first = consume_policy_assignment_definition(policy_before,
            policy_name=binding.policy_name, serial_digest=binding.serial_digest)
        last = consume_policy_assignment_definition(policy_after,
            policy_name=binding.policy_name, serial_digest=binding.serial_digest)
        if (first != last or _folder(folder_after, binding) != (folder, inherited)
                or _secret(secret_after, binding) != secret):
            raise ValueError
        relation = _digest((CONTRACT, binding.serial_digest, secret, folder, first.state_digest))
        return PolicyAssignmentRelation(secret, folder, first.configuration_digest, first.state_digest,
            relation, inherited, first.controls)
    except Exception:
        raise PolicyAssignmentRelationError(_ERROR) from None
    finally:
        for content in buffers:
            if type(content) is bytearray:
                _zeroize_mutable(content)
