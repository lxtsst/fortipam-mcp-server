"""Private full Web Secret retention across one intended Policy-reference change.

Reuse the existing build29 Web detail, Password and disabled-empty TOTP witness
contracts. Only the qualified root Policy reference and volatile TOTP render are
replaced in the complete row fingerprint. This pure consumer grants no source,
fixture, assignment, restoration or material-retrieval authority.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import re

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from .secret_approval_build29_native_preservation import _qualify_bracket
from .secret_approval_build29_totp_boundary import SecretApprovalBuild29TotpWitness
from .secret_instruction_build29_api_preservation import (
    SecretInstructionBuild29CredentialWitness, _credential_bracket, _key, _qualify_web_detail,
)
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = "fortipam-build29-policy-assignment-full-secret-preservation-v1"
_ERROR = "The private Policy-assignment Secret preservation witness is unavailable."
_NAME = re.compile(r'[^/\\\x00-\x1f\x7f]{1,64}\Z')


class PolicyAssignmentPreservationError(ValueError):
    """Fixed refusal without any partial private source or upstream detail."""


@dataclass(frozen=True, slots=True, repr=False)
class PolicyAssignmentPreservation(_OpaqueC3Object):
    preservation_digest: str

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT, complete_response_row_tokens_bound=True,
            password_and_disabled_empty_totp_brackets_matched=True,
            only_policy_reference_and_totp_render_excluded=True,
            source_completeness_qualified=False, source_provenance_qualified=False,
            original_ownership_qualified=False, assignment_authorized=False,
            material_or_digest_returned=False)


def consume_policy_assignment_preservation(content: bytearray, *, identity: Mapping[str, object],
        serial_digest: str, expected_policy_name: str,
        credential_before: SecretInstructionBuild29CredentialWitness,
        credential_after: SecretInstructionBuild29CredentialWitness,
        totp_before: SecretApprovalBuild29TotpWitness, totp_after: SecretApprovalBuild29TotpWitness,
        witness_key: bytes | bytearray) -> PolicyAssignmentPreservation:
    """Bind the full detail row plus independently source-qualified materials.

    The fixed profile is a targetless Web Account with no Instruction Profile
    and disabled, explicitly empty TOTP. Policy is the only intended association
    change. Every other row byte, including unknown fields, computed permission,
    credential-slot renders and nested Policy-like keys, remains significant.
    The producer must independently qualify one complete unprojected GET and
    the exact Password/TOTP requests on the same actor/Secret/key/fresh window.
    Masked CMDB tokens and caller-created witness objects never prove that.
    """
    field = bytearray()
    try:
        _key(witness_key, content)
        if type(expected_policy_name) is not str or _NAME.fullmatch(expected_policy_name) is None:
            raise ValueError
        left, right, _, password_field_id, shared = _qualify_web_detail(content,
            identity=identity, serial_digest=serial_digest, instruction_profile_name="", field=field)
        policy = metadata._object_spans(content, left, right, frozenset({"policy"}))["policy"]
        if metadata._scalar(content, policy) != expected_policy_name:
            raise ValueError
        secret_id = metadata._integer(identity["id"])
        _credential_bracket(credential_before, credential_after, secret_id=secret_id,
            field_id=password_field_id, key=witness_key)
        _qualify_bracket(totp_before, totp_after, witness_key)
        if totp_before.explicit_empty is not True:
            raise ValueError
        replacements = sorted([(policy, b'"policy-reference-excluded"'),
            (shared, b'"totp-semantic:' + totp_before.material_digest.encode("ascii") + b'"')])
        digest = hmac.new(witness_key, digestmod=hashlib.sha256)
        digest.update(CONTRACT.encode("ascii") + b"\0" + serial_digest.encode("ascii") + b"\0")
        digest.update(credential_before.material_digest.encode("ascii"))
        cursor = left
        for (first, last), replacement in replacements:
            if not cursor <= first < last <= right:
                raise ValueError
            with memoryview(content)[cursor:first] as view:
                digest.update(view)
            digest.update(replacement)
            cursor = last
        with memoryview(content)[cursor:right] as view:
            digest.update(view)
        return PolicyAssignmentPreservation(digest.hexdigest())
    except Exception:
        raise PolicyAssignmentPreservationError(_ERROR) from None
    finally:
        try:
            _zeroize_mutable(field)
        finally:
            if type(content) is bytearray:
                _zeroize_mutable(content)
