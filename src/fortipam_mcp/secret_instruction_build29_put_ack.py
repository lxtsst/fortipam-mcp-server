"""Inactive byte-only acknowledgement consumer for one-field Instruction PUTs.

The trusted producer must bind the actual request, original normal Web creation,
Profile custody and M4 claim. These pins and witnesses supply no provenance,
dispatch, restoration or execution authority by themselves. No transport, durable
ACK, Tool, startup activation or source-status observation is provided here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Literal

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from .instruction_profile_contract import _NAME
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

_ERROR = "The private Secret Instruction PUT acknowledgement is unavailable."
_MAX = 16_384
_DOMAIN = b"fortipam-build29-secret-instruction-put-ack/v1\x00"
_FIELDS = frozenset({"version", "build", "http_method", "http_status", "status", "path", "name",
    "vdom", "serial", "mkey", "error", "action", "schema_errors", "results"})
_REQUIRED = _FIELDS - {"error", "action", "schema_errors", "results"}


class SecretInstructionBuild29PutAckError(ValueError):
    """Categorical refusal without response, material or selector values."""
    def __init__(self) -> None:
        super().__init__(_ERROR)


@dataclass(frozen=True, slots=True, repr=False)
class SecretInstructionBuild29PutAckPins(_OpaqueC3Object):
    """Private exact dispatch constraints; a caller cannot use them as authority."""
    native_secret_id: int
    serial_digest: str
    creation_digest: str
    instruction_profile_name: str
    phase: Literal["attach", "restore"]
    plan_digest: str
    authorization_digest: str
    success_status: Literal["OK", "success"]
    retained_body_digest: str | None = None

    def __post_init__(self) -> None:
        try:
            if (type(self.native_secret_id) is not int or not 0 < self.native_secret_id <= 2_147_483_647
                    or type(self.instruction_profile_name) is not str
                    or _NAME.fullmatch(self.instruction_profile_name) is None
                    or type(self.phase) is not str or self.phase not in {"attach", "restore"}
                    or type(self.success_status) is not str or self.success_status not in {"OK", "success"}):
                raise ValueError
            for digest in (self.serial_digest, self.creation_digest, self.plan_digest, self.authorization_digest):
                require_digest(digest, "ack_context_digest")
            if self.retained_body_digest is not None:
                require_digest(self.retained_body_digest, "retained_body_digest")
        except Exception:
            raise SecretInstructionBuild29PutAckError() from None

    @property
    def context_digest(self) -> str:
        self.__post_init__()
        reference = self.instruction_profile_name.encode("ascii") if self.phase == "attach" else b""
        body_digest = hashlib.sha256(b'{"instruction-profile":"' + reference + b'"}').hexdigest()
        if self.retained_body_digest is not None:
            body_digest = self.retained_body_digest
        return canonical_digest({"contract": "secret-instruction-put-ack/v1" if self.retained_body_digest is None
            else "secret-instruction-retained-put-ack/v2", "phase": self.phase,
            "native_secret_id": self.native_secret_id, "serial_digest": self.serial_digest,
            "creation_digest": self.creation_digest, "instruction_profile_name": self.instruction_profile_name,
            "body_digest": body_digest,
            "plan_digest": self.plan_digest, "authorization_digest": self.authorization_digest,
            "success_status": self.success_status})


@dataclass(frozen=True, slots=True, repr=False)
class SecretInstructionBuild29PutAcknowledgement(_OpaqueC3Object):
    """Private key-bound response witness; never an original-ACK custody proof."""
    context_digest: str
    acknowledgement_digest: str


def consume_secret_instruction_build29_put_ack(raw: bytearray, *,
        pins: SecretInstructionBuild29PutAckPins, http_status: int, content_type: str,
        witness_key: bytes | bytearray) -> SecretInstructionBuild29PutAcknowledgement:
    """Require exact PUT200/build29/device/object metadata and wipe every input.

    Only compiled envelope scalars are decoded. Unknown values are validated as
    JSON bytes and erased. Results, action and schema-error payloads refuse;
    duplicate selected envelope keys, multiple JSON documents and oversized
    inputs also refuse.
    Status must equal the separately qualified pin; POST/DELETE status evidence
    cannot qualify PUT merely by constructing a pin. Native ACK alone does not
    establish complete preservation or a successful original M4 terminal claim.
    """
    from . import secret_bulk_import_metadata as metadata
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= _MAX
                or type(pins) is not SecretInstructionBuild29PutAckPins
                or type(http_status) is not int or http_status != 200
                or type(content_type) is not str or len(content_type) > 128
                or content_type.split(";", 1)[0].strip().lower() != "application/json"
                or type(witness_key) not in (bytes, bytearray) or witness_key is raw
                or not 32 <= len(witness_key) <= 128):
            raise ValueError
        context = pins.context_digest
        left = _skip_json_space(raw, 0)
        right = _json_value_end(raw, left)
        if _skip_json_space(raw, right) != len(raw):
            raise ValueError
        metadata._validate_json(raw, left, right, depth=0, budget=[50_000])
        spans = metadata._object_spans(raw, left, right, _FIELDS)
        if not _REQUIRED <= spans.keys() or {"action", "schema_errors", "results"} & spans.keys():
            raise ValueError
        expected: dict[str, str | int] = {"version": "v7.0.0", "build": 29, "http_method": "PUT",
            "http_status": 200, "status": pins.success_status, "path": "secret", "name": "database",
            "vdom": "root", "mkey": pins.native_secret_id}
        for name, wanted in expected.items():
            actual = metadata._scalar(raw, spans[name])
            if type(actual) is not type(wanted) or actual != wanted:
                raise ValueError
        serial = metadata._text(metadata._scalar(raw, spans["serial"]), maximum=128)
        if not hmac.compare_digest(hashlib.sha256(serial.encode()).hexdigest(), pins.serial_digest):
            raise ValueError
        if "error" in spans:
            actual = metadata._scalar(raw, spans["error"])
            if type(actual) is not int or actual != 0:
                raise ValueError
        digest = hmac.new(witness_key, _DOMAIN + context.encode("ascii") + b"\x00", hashlib.sha256)
        digest.update(raw)
        return SecretInstructionBuild29PutAcknowledgement(context, digest.hexdigest())
    except Exception:
        raise SecretInstructionBuild29PutAckError() from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)
