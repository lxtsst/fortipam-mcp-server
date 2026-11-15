"""Private fixed Web update projection; no transport or execution authority.

Reuse the accepted Web field serializer shape. Retained values remain mutable
JSON bytes; the caller must independently bind complete configuration and clear
Password/TOTP preservation before dispatch and wipe the returned body afterward.
"""
from collections.abc import Mapping
import json

from .instruction_profile_contract import _NAME
from .secret_approval_build29_web_fields import _slots
from .secret_instruction_build29_api_preservation import _qualify_web_detail
from .secret_metadata_http_transport import _zeroize_mutable


def compile_instruction_retained_web_body(raw: bytearray, *, identity: Mapping[str, object],
        serial_digest: str, current_reference: str, proposed_reference: str) -> bytearray:
    """Consume one exact full GET and project identity, delta and three slots.

    Only empty-to-named attach and named-to-empty restore are supported. The
    original slot id/name/value encodings are retained without decoding values.
    This projection alone does not prove material preservation or authorize PUT.
    """
    field, output = bytearray(), bytearray()
    succeeded = False
    try:
        if (type(proposed_reference) is not str
                or proposed_reference and _NAME.fullmatch(proposed_reference) is None
                or type(current_reference) is not str
                or bool(current_reference) == bool(proposed_reference)):
            raise ValueError
        _qualify_web_detail(raw, identity=identity, serial_digest=serial_digest,
            instruction_profile_name=current_reference, field=field)
        slots = _slots(field)
        routing = {key: identity[key] for key in ("id", "name", "folder", "template")}
        output.extend(json.dumps({**routing, "instruction-profile": proposed_reference},
            separators=(",", ":")).encode()[:-1])
        output.extend(b',"field":[')
        for index, name in enumerate(("Password", "URL", "Username")):
            if index: output.extend(b",")
            output.extend(b"{")
            for position, key in enumerate(("id", "name", "value")):
                if position: output.extend(b",")
                output.extend(b'"' + key.encode("ascii") + b'":')
                with memoryview(field)[slice(*slots[name][key])] as value:
                    output.extend(value)
            output.extend(b"}")
        output.extend(b"]}")
        succeeded = True
        return output
    except Exception:
        raise ValueError("The private retained Web Instruction body is unavailable.") from None
    finally:
        _zeroize_mutable(field)
        if type(raw) is bytearray: _zeroize_mutable(raw)
        if not succeeded: _zeroize_mutable(output)
