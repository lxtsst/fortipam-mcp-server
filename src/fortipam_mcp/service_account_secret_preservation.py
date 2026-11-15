"""Private complete Secret retention joined to dependency/Target/Updater state.

No source, material retrieval, ownership, dispatch or recovery authority is
provided. A producer must independently qualify complete unprojected rows and
the exact same-subject Password/TOTP reads. Metadata-only reader results and
masked field renders cannot supply those witnesses.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .local_user_reset_projection import _object_spans
from .secret_approval_build29_native_preservation import _qualify_bracket
from .secret_approval_build29_totp_boundary import SecretApprovalBuild29TotpWitness
from .secret_instruction_build29_api_preservation import (
    SecretInstructionBuild29CredentialWitness, _credential_bracket,
)
from .secret_metadata_http_transport import _zeroize_mutable
from .service_account_state_projection import (
    ServiceAccountStateBinding, ServiceAccountStateProjection, _SECRET, _detail, _secret,
    consume_service_account_state,
)
from .target_preservation_contract import _token_digest

CONTRACT = "fortipam-build29-service-account-secret-preservation-private-v1"
_ERROR = "The private service-account Secret preservation is unavailable."
_IDENTITY = frozenset({"id", "name", "uuid", "folder", "template", "target"})
_REQUIRED = _IDENTITY | {"dependency", "field", "totp-setting"}


class ServiceAccountSecretPreservationError(ValueError):
    """Fixed refusal without response values or partial private evidence."""


@dataclass(frozen=True, slots=True, repr=False)
class ServiceAccountSecretMaterialBracket(_OpaqueC3Object):
    """Supplied private witnesses, never source qualification by themselves."""
    password_before: SecretInstructionBuild29CredentialWitness
    password_after: SecretInstructionBuild29CredentialWitness
    totp_before: SecretApprovalBuild29TotpWitness
    totp_after: SecretApprovalBuild29TotpWitness


@dataclass(frozen=True, slots=True, repr=False)
class ServiceAccountPreservedState(_OpaqueC3Object):
    relationship: ServiceAccountStateProjection
    secret_preservation_digest: str
    state_digest: str

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT, supplied_complete_secret_row_tokens_bound=True,
            supplied_password_and_disabled_empty_totp_brackets_matched=True,
            dependency_target_updater_brackets_matched=True,
            only_direct_totp_shared_key_render_replaced=True,
            source_completeness_qualified=False, source_provenance_qualified=False,
            complete_secret_preservation_qualified=False,
            original_ownership_qualified=False, credential_consistency_qualified=False,
            permission_qualified=False, recovery_qualified=False,
            execution_authorized=False, runtime_registered=False,
            private_values_or_digests_returned=False)


def _declared_identity(binding: ServiceAccountStateBinding, identity: Mapping[str, object], row_fields: frozenset[str]) -> dict[str, object]:
    if (type(binding) is not ServiceAccountStateBinding or not isinstance(identity, Mapping) or set(identity) != _IDENTITY
            or type(row_fields) is not frozenset or not _REQUIRED <= row_fields or len(row_fields) > 512
            or any(type(name) is not str for name in row_fields)):
        raise ValueError
    binding.__post_init__()
    expected = dict(identity)
    for name, value in dict(id=binding.secret_id, name=binding.secret_name, uuid=binding.secret_uuid).items():
        if type(expected[name]) is not type(value) or expected[name] != value: raise ValueError
    m._integer(expected["folder"])
    for name in ("template", "target"): m._text(expected[name], maximum=127)
    return expected


def _source_frame(raw: bytearray, *, binding: ServiceAccountStateBinding,
        identity: Mapping[str, object], row_fields: frozenset[str]
        ) -> tuple[int, int, dict[str, tuple[int, int]], int, tuple[int, int]]:
    left, right = _detail(raw, "database", binding, status="OK")
    row = _object_spans(raw, left, right)
    if set(row) != row_fields: raise ValueError
    for name, expected in identity.items():
        actual = m._scalar(raw, row[name])
        if type(actual) is not type(expected) or actual != expected: raise ValueError
    if "q_origin_key" in row:
        origin = m._scalar(raw, row["q_origin_key"])
        if not ((type(origin) is int and origin == binding.secret_id)
                or (type(origin) is str and origin == str(binding.secret_id))): raise ValueError
    password_field_id: int | None = None
    names: set[str] = set()
    identifiers: set[int] = set()
    for entry in m._array(raw, row["field"], 64):
        fields = _object_spans(raw, *entry)
        if not {"id", "name", "value"} <= fields.keys(): raise ValueError
        identifier = m._integer(m._scalar(raw, fields["id"]))
        name = m._text(m._scalar(raw, fields["name"]), maximum=64)
        if name in names or identifier in identifiers or raw[fields["value"][0]] != 34: raise ValueError
        names.add(name); identifiers.add(identifier)
        if name == "Password": password_field_id = identifier
    if password_field_id is None or "Username" not in names: raise ValueError
    totp = _object_spans(raw, *row["totp-setting"])
    if m._scalar(raw, totp["status"]) != "disable": raise ValueError
    shared = totp["shared-key"]
    if raw[shared[0]] != 34 and raw[slice(*shared)] != b"null": raise ValueError
    return left, right, row, password_field_id, shared


def _metadata_copy(raw: bytearray, left: int, right: int, row: Mapping[str, tuple[int, int]]) -> bytearray:
    output = bytearray()
    transferred = False
    try:
        output.extend(raw[:left]); output.extend(b"{")
        for index, name in enumerate(sorted(_SECRET)):
            if index: output.extend(b",")
            output.extend(b'"' + name.encode("ascii") + b'":')
            with memoryview(raw)[slice(*row[name])] as value: output.extend(value)
        output.extend(b"}"); output.extend(raw[right:])
        transferred = True
        return output
    finally:
        if not transferred: _zeroize_mutable(output)


def inspect_service_account_secret_password_field(raw: bytearray, *, binding: ServiceAccountStateBinding,
        secret_identity: Mapping[str, object], secret_row_fields: frozenset[str], witness_key: bytes) -> int:
    """Check a supplied complete row before any separately authorized material read.

    Success borrows the unchanged buffer for the later preservation consumer;
    failure/interrupt wipes it. The returned private field ID does not establish
    native completeness, material provenance, ownership or lookup authority.
    """
    accepted = False; narrow = bytearray()
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= m._MAX_BYTES
                or type(witness_key) is not bytes or len(witness_key) != 32): raise ValueError
        identity = _declared_identity(binding, secret_identity, secret_row_fields)
        left, right, row, field_id, _ = _source_frame(raw, binding=binding, identity=identity, row_fields=secret_row_fields)
        narrow = _metadata_copy(raw, left, right, row)
        _secret(narrow, binding, witness_key)
        accepted = True
        return field_id
    except Exception: raise ServiceAccountSecretPreservationError(_ERROR) from None
    finally:
        _zeroize_mutable(narrow)
        if not accepted and type(raw) is bytearray: _zeroize_mutable(raw)


def _frame(raw: bytearray, *, binding: ServiceAccountStateBinding,
        identity: Mapping[str, object], row_fields: frozenset[str],
        material: ServiceAccountSecretMaterialBracket, key: bytes) -> tuple[str, bytearray]:
    """Retain all row tokens; return only a narrow private metadata copy."""
    output = bytearray()
    transferred = False
    try:
        left, right, row, password_field_id, shared = _source_frame(raw, binding=binding, identity=identity, row_fields=row_fields)
        if type(material) is not ServiceAccountSecretMaterialBracket:
            raise ValueError
        _credential_bracket(material.password_before, material.password_after,
            secret_id=binding.secret_id, field_id=password_field_id, key=key)
        _qualify_bracket(material.totp_before, material.totp_after, key)
        if material.totp_before.explicit_empty is not True:
            raise ValueError

        # No string value is decoded. Only the direct volatile TOTP render is
        # substituted, with mandatory independent explicit-empty witnesses.
        digest = hmac.new(key, CONTRACT.encode("ascii") + b"\0", hashlib.sha256)
        for token in (binding.serial_digest,
                _token_digest(raw, (left, shared[0])),
                material.totp_before.material_digest,
                _token_digest(raw, (shared[1], right)),
                material.password_before.material_digest):
            digest.update(token.encode("ascii"))

        # Reuse the exact existing dependency/Target/Updater consumer without
        # passing credential-bearing bytes through its redaction decoder.
        output = _metadata_copy(raw, left, right, row)
        transferred = True
        return digest.hexdigest(), output
    finally:
        if not transferred:
            _zeroize_mutable(output)


def consume_service_account_preserved_state(*, binding: ServiceAccountStateBinding,
        secret_identity: Mapping[str, object], secret_row_fields: frozenset[str],
        witness_key: bytes, material_before: ServiceAccountSecretMaterialBracket,
        material_after: ServiceAccountSecretMaterialBracket,
        secret_before: bytearray, target_before: bytearray, updater_before: bytearray,
        updater_after: bytearray, target_after: bytearray,
        secret_after: bytearray) -> ServiceAccountPreservedState:
    """Consume six buffers, complete row-field pins and two material brackets.

    Identity/row-field pins and witness objects are protected producer inputs,
    not completeness, original custody or provenance evidence. The producer
    must establish those independently before any native use. This consumer
    permits no intended row change, even in a dependency runtime field, and
    grants no update or restoration authority. Order/string-token differences
    conservatively refuse; insignificant whitespace may differ.
    """
    buffers = (secret_before, target_before, updater_before, updater_after, target_after, secret_after)
    projected: list[bytearray] = []
    try:
        if (type(binding) is not ServiceAccountStateBinding
                or type(witness_key) is not bytes or len(witness_key) != 32
                or any(type(raw) is not bytearray or not 0 < len(raw) <= m._MAX_BYTES for raw in buffers)
                or len({id(raw) for raw in buffers}) != 6):
            raise ValueError
        identity = _declared_identity(binding, secret_identity, secret_row_fields)

        first, narrow = _frame(secret_before, binding=binding, identity=identity,
            row_fields=secret_row_fields, material=material_before, key=witness_key)
        projected.append(narrow)
        second, narrow = _frame(secret_after, binding=binding, identity=identity,
            row_fields=secret_row_fields, material=material_after, key=witness_key)
        projected.append(narrow)
        if not hmac.compare_digest(first, second):
            raise ValueError
        state = consume_service_account_state(binding=binding, witness_key=witness_key,
            secret_before=projected[0], target_before=target_before, updater_before=updater_before,
            updater_after=updater_after, target_after=target_after, secret_after=projected[1])
        combined = hmac.new(witness_key, CONTRACT.encode("ascii") + b"\0" +
            state.relation_digest.encode("ascii") + first.encode("ascii"), hashlib.sha256).hexdigest()
        return ServiceAccountPreservedState(state, first, combined)
    except Exception:
        raise ServiceAccountSecretPreservationError(_ERROR) from None
    finally:
        for raw in (*buffers, *projected):
            if type(raw) is bytearray:
                _zeroize_mutable(raw)
