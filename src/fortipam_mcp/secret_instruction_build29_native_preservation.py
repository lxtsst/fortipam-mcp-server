"""Inactive private full-native witness for one Instruction-only transition.

The trusted producer must qualify the complete CLI frame, version, serial,
subject, field rendering and both same-key TOTP sources. This pure consumer
does not read a device, import ownership or grant execution/recovery authority.
"""

from dataclasses import dataclass
import hashlib
import hmac

from .folder_namespace_ssh_reader import _MAX_OUTPUT_BYTES
from .instruction_profile_contract import _NAME
from .secret_approval_build29_native_preservation import (
    _compose, _qualify_bracket, _safe_name,
)
from .secret_approval_build29_totp_boundary import SecretApprovalBuild29TotpWitness
from .secret_metadata_http_transport import _zeroize_mutable


_DOMAIN = b"fortipam-700-build29-instruction-full-native-totp-preservation-v1\x00"
_FIELDS = (b"instruction-profile",)
_UNAVAILABLE = "The private Secret Instruction preservation witness is unavailable."


class SecretInstructionBuild29NativePreservationError(RuntimeError):
    """Categorical refusal without protected source values or parser details."""

    def __init__(self) -> None:
        super().__init__(_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class SecretInstructionBuild29NativePreservationWitness:
    """Private keyed digest, never an MCP result, plan or audit field."""

    preservation_digest: str


def consume_secret_instruction_build29_native_preservation(
    raw: bytearray, *, expected_secret_id: int, expected_secret_name: str,
    instruction_profile_name: str,
    totp_before: SecretApprovalBuild29TotpWitness,
    totp_after: SecretApprovalBuild29TotpWitness,
    witness_key: bytes | bytearray,
) -> SecretInstructionBuild29NativePreservationWitness:
    """Consume a complete qualified frame; exclude only its exact reference.

    A nonempty reference requires one root ``set instruction-profile "name"``
    line. Empty means the line is absent; any explicit set/unset, nested or
    duplicate occurrence refuses. These strict renderings still need live source
    qualification for the new producer before activation; an empty API reference
    alone does not qualify an omitted CLI field.

    The complete non-Instruction native content remains in the digest, including
    approval settings, unknown members, every credential ENC value and UUID.
    Only the unique direct TOTP shared-key ENC render is replaced with the
    separately bracketed semantic HMAC, as in the existing approval consumer.
    A masked metadata projection cannot supply this full-native input. A digest
    comparison does not independently qualify sources or cleartext credentials.
    No protected scalar is decoded or returned; raw input is wiped on every exit.
    """
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= _MAX_OUTPUT_BYTES
                or type(expected_secret_id) is not int
                or not 0 < expected_secret_id <= 2_147_483_647
                or not _safe_name(expected_secret_name, 64)
                or type(instruction_profile_name) is not str
                or (instruction_profile_name and _NAME.fullmatch(instruction_profile_name) is None)
                or type(witness_key) not in (bytes, bytearray)
                or witness_key is raw or len(witness_key) < 32):
            raise ValueError
        _qualify_bracket(totp_before, totp_after, witness_key)
        expected_fields = []
        if instruction_profile_name:
            expected_fields.append(b'set instruction-profile "'
                                   + instruction_profile_name.encode("ascii") + b'"')
        semantic = (b"semantic-hmac-sha256:" + totp_before.material_digest.encode("ascii")
                    + (b":empty=1" if totp_before.explicit_empty else b":empty=0"))
        digest = hmac.new(witness_key, digestmod=hashlib.sha256)
        digest.update(_DOMAIN)
        _compose(raw, b"edit " + str(expected_secret_id).encode("ascii"),
                 b'set name "' + expected_secret_name.encode("ascii") + b'"',
                 expected_fields, semantic, digest, excluded_fields=_FIELDS)
        return SecretInstructionBuild29NativePreservationWitness(digest.hexdigest())
    except Exception:
        raise SecretInstructionBuild29NativePreservationError() from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)
