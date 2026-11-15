"""Private build29 dependency/Target/Updater join; no I/O or action authority.

Consume two copies of each fixed detail. Bind the complete dependency collection,
all 36 Target configuration fields and all seven Updater configuration fields.
Secret credential fields are erased before framing and never contribute to a
material-preservation claim. Runtime status, datetime, message and commands stay
opaque: matching tokens do not establish successful execution or availability.
Source order, freshness, actor and route provenance belong to the future reader.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
import uuid

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .secret_metadata_http_transport import (
    _json_value_end, _redact_json_field_values, _skip_json_space, _zeroize_mutable,
)
from .target_lifecycle_dependencies import _one, _spans
from .target_preservation_contract import (
    TargetState, _digest, _member_count, _token_digest, capture_target_state,
)

CONTRACT = "fortipam-build29-service-account-state-projection-private-v1"
_ERROR = "The private service-account state projection is unavailable."
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_SECRET = frozenset({"id", "name", "uuid", "dependency"})
_DEPENDENCY = frozenset({"id", "target", "updater", "last-update", "status", "msg"})
_UPDATER = frozenset({"name", "type", "restart", "service-name", "file-path",
                      "replace-cmd", "restart-cmd"})
# Observed together on the complete build29 b47 detail, updater-detail-r1.
# Values remain opaque and significant; this list does not authorize adoption.
_UPDATER_METADATA = frozenset({"q_global_entry", "q_mkey_type", "q_name", "q_no_edit",
    "q_no_rename", "q_origin_key", "q_path", "q_ref", "q_static", "q_type"})
_ENVELOPE = m._ENVELOPE_FIELDS | frozenset({"mkey", "matched_count", "action"})


class ServiceAccountStateProjectionError(ValueError):
    """Fixed refusal without native values, partial state or upstream errors."""


@dataclass(frozen=True, slots=True, repr=False)
class ServiceAccountStateBinding(_OpaqueC3Object):
    """Private selectors/context assertions, never source or ownership proof."""
    secret_id: int
    secret_name: str
    secret_uuid: str
    dependency_id: int
    target_name: str
    updater_name: str
    serial_digest: str
    source_context_digest: str

    def __post_init__(self) -> None:
        try:
            for identifier, maximum in ((self.secret_id, 2_147_483_647), (self.dependency_id, 64)):
                if type(identifier) is not int or not 0 < identifier <= maximum:
                    raise ValueError
            for text, maximum in ((self.secret_name, 255), (self.target_name, 127),
                                   (self.updater_name, 79)):
                m._text(text, maximum=maximum)
            if (type(self.secret_uuid) is not str or not uuid.UUID(self.secret_uuid).int
                    or str(uuid.UUID(self.secret_uuid)) != self.secret_uuid):
                raise ValueError
            for digest in (self.serial_digest, self.source_context_digest):
                if type(digest) is not str or _HEX.fullmatch(digest) is None:
                    raise ValueError
        except Exception:
            raise ServiceAccountStateProjectionError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class ServiceAccountStateProjection(_OpaqueC3Object):
    dependency_count: int
    dependency_digest: str
    target_state_digest: str
    updater_state_digest: str
    relation_digest: str
    bounded_windows_service_profile: bool

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT, complete_dependency_collection_bound=True,
            complete_target_configuration_fields=36, complete_updater_configuration_fields=7,
            selected_relationship_matched=True, supplied_bracket_tokens_stable=True,
            bounded_windows_service_profile=self.bounded_windows_service_profile,
            runtime_status_interpreted=False, runtime_wire_contract_qualified=False,
            complete_secret_preservation_qualified=False,
            credential_consistency_qualified=False, source_provenance_qualified=False,
            permission_qualified=False, recovery_qualified=False,
            execution_authorized=False, runtime_registered=False, private_values_returned=False)


def _fingerprint(raw: bytearray, span: tuple[int, int], key: bytes, domain: str) -> str:
    # No opaque string reaches a decoder; the private key prevents dictionary
    # checks against retained message/command/configuration fingerprints.
    return hmac.new(key, domain.encode("ascii") + b"\0" +
        _token_digest(raw, span).encode("ascii"), hashlib.sha256).hexdigest()


def _exact(raw: bytearray, span: tuple[int, int], required: frozenset[str],
           optional: frozenset[str] = frozenset()) -> dict[str, tuple[int, int]]:
    fields = m._object_spans(raw, *span, required | optional)
    if not required <= fields.keys() or len(fields) != _member_count(raw, span):
        raise ValueError
    return fields


def _detail(raw: bytearray, table: str, binding: ServiceAccountStateBinding,
            *, status: str) -> tuple[int, int]:
    _spans(raw)
    expected_fields = dict(version="v7.0.0", build=29, path="secret", name=table,
        http_method="GET", http_status=200, status=status, vdom="root")
    start = _skip_json_space(raw, 0)
    envelope = _exact(raw, (start, _json_value_end(raw, start)),
        frozenset(expected_fields) | {"serial", "results"}, _ENVELOPE)
    for name, expected in expected_fields.items():
        actual = m._scalar(raw, envelope[name])
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError
    serial = m._text(m._scalar(raw, envelope["serial"]), maximum=128)
    if hashlib.sha256(serial.encode()).hexdigest() != binding.serial_digest or "action" in envelope:
        raise ValueError
    if "error" in envelope:
        error = m._scalar(raw, envelope["error"])
        if error is not None and (type(error) is not int or error != 0):
            raise ValueError
    if "limit_reached" in envelope and m._scalar(raw, envelope["limit_reached"]) is not False:
        raise ValueError
    for name in ("size", "matched_count", "next_idx"):
        if name in envelope:
            value = m._scalar(raw, envelope[name])
            if type(value) is not int or value not in ((0, 1) if name == "next_idx" else (1,)):
                raise ValueError
    expected_key = binding.secret_id if table == "database" else (
        binding.target_name if table == "target" else binding.updater_name)
    if "mkey" in envelope:
        value = m._scalar(raw, envelope["mkey"])
        if type(value) is not type(expected_key) or value != expected_key:
            raise ValueError
    return _one(raw, envelope["results"])


def _target(raw: bytearray, binding: ServiceAccountStateBinding) -> TargetState:
    _detail(raw, "target", binding, status="success")
    return capture_target_state(raw, expected_name=binding.target_name,
        expected_serial_digest=binding.serial_digest)


def _secret(raw: bytearray, binding: ServiceAccountStateBinding, key: bytes) -> tuple[int, str]:
    _redact_json_field_values(raw)
    span = _detail(raw, "database", binding, status="OK")
    fields = _exact(raw, span, _SECRET, frozenset({"field"}))
    for name, expected in dict(id=binding.secret_id, name=binding.secret_name,
                               uuid=binding.secret_uuid).items():
        actual = m._scalar(raw, fields[name])
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError
    entries = m._array(raw, fields["dependency"], 64)
    identifiers: set[int] = set()
    matched = False
    for entry in entries:
        row = _exact(raw, entry, _DEPENDENCY)
        identifier = m._scalar(raw, row["id"])
        if type(identifier) is not int or not 1 <= identifier <= 64 or identifier in identifiers:
            raise ValueError
        identifiers.add(identifier)
        target = m._text(m._scalar(raw, row["target"]), maximum=127)
        updater = m._text(m._scalar(raw, row["updater"]), maximum=79)
        # Native option/var-string values remain opaque strings. The datetime
        # wire format is not qualified: preserve it without interpreting it.
        if any(raw[row[name][0]] != 34 for name in ("status", "msg")):
            raise ValueError
        if identifier == binding.dependency_id:
            if (target, updater) != (binding.target_name, binding.updater_name):
                raise ValueError
            matched = True
    if not matched:
        raise ValueError
    return len(entries), _fingerprint(raw, fields["dependency"], key, "dependency-collection")


def _updater(raw: bytearray, binding: ServiceAccountStateBinding, key: bytes) -> tuple[str, bool]:
    span = _detail(raw, "dependency-updater", binding, status="success")
    fields = _exact(raw, span, _UPDATER, _UPDATER_METADATA)
    if m._scalar(raw, fields["name"]) != binding.updater_name:
        raise ValueError
    if "q_origin_key" in fields and m._scalar(raw, fields["q_origin_key"]) != binding.updater_name:
        raise ValueError
    for name in _UPDATER:
        if raw[fields[name][0]] != 34:
            raise ValueError
    # Compare fixed safe tokens without decoding a service name, path or command.
    profile = (raw[slice(*fields["type"])] == b'"win-service"'
        and raw[slice(*fields["restart"])] == b'"disable"'
        and all(raw[slice(*fields[name])] == b'""'
                for name in ("file-path", "replace-cmd", "restart-cmd"))
        and re.fullmatch(rb'"[A-Za-z0-9][A-Za-z0-9._$-]{0,63}"',
                         raw[slice(*fields["service-name"])]) is not None)
    return _fingerprint(raw, span, key, "complete-updater"), profile


def consume_service_account_state(*, binding: ServiceAccountStateBinding, witness_key: bytes,
        secret_before: bytearray, target_before: bytearray, updater_before: bytearray,
        updater_after: bytearray, target_after: bytearray,
        secret_after: bytearray) -> ServiceAccountStateProjection:
    """Consume six distinct buffers; no freshness, provenance or material witness.

    Secret detail is the fixed id/name/uuid/dependency projection. A native field
    array sent despite format is erased, and every other unknown root field is
    refused. Only complete native Target/Updater rows are accepted. Caller-supplied
    context digests bind inputs, not their origin. Every buffer clears on failure.
    """
    buffers = (secret_before, target_before, updater_before, updater_after, target_after, secret_after)
    try:
        if (type(binding) is not ServiceAccountStateBinding or type(witness_key) is not bytes
                or len(witness_key) != 32
                or any(type(raw) is not bytearray or not 0 < len(raw) <= m._MAX_BYTES for raw in buffers)
                or len({id(raw) for raw in buffers}) != 6):
            raise ValueError
        binding.__post_init__()
        first_secret = _secret(secret_before, binding, witness_key)
        first_target = _target(target_before, binding)
        first_updater = _updater(updater_before, binding, witness_key)
        if (_updater(updater_after, binding, witness_key) != first_updater
                or _target(target_after, binding) != first_target
                or _secret(secret_after, binding, witness_key) != first_secret):
            raise ValueError
        count, dependency = first_secret
        updater, profile = first_updater
        relation = _digest((CONTRACT, binding.source_context_digest, binding.serial_digest,
            binding.secret_id, binding.secret_name, binding.secret_uuid, binding.dependency_id,
            binding.target_name, binding.updater_name, dependency, first_target.state_digest, updater))
        return ServiceAccountStateProjection(count, dependency, first_target.state_digest,
            updater, relation, profile)
    except Exception:
        raise ServiceAccountStateProjectionError(_ERROR) from None
    finally:
        for raw in buffers:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)
