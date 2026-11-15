"""Inactive one-field Secret Instruction association compiler for build29.

Only minimized metadata may enter this pure candidate. A qualified producer,
owned Secret/Profile proofs, partial-PUT ACK, complete preservation, authorization
and original-ACK recovery remain separate requirements. No Tool or transport is
provided; compiling a body never authorizes a write or proves Profile existence.
"""
from collections.abc import Mapping

from .instruction_profile_contract import _NAME
from .secret_metadata_http_transport import _bounded_name

CONTRACT = "fortipam-700-build29-secret-instruction-transition-candidate-v1"
FIELD = "instruction-profile"
_IDENTITY = frozenset({"id", "name", "folder", "template"})
_ERROR = "The private Secret Instruction association candidate is unavailable."


class SecretInstructionBuild29ContractError(ValueError):
    """Categorical refusal without input values or selectors."""


def qualify_secret_instruction_build29_schema(schema: object) -> None:
    """Require the minimized, observed string/single-reference/default facts."""
    try:
        expected: dict[str, object] = {
            "type": "string", "size": 79, "default": "", "multiple_values": False,
            "datasource": ["secret.instruction-profile.name"],
        }
        if (not isinstance(schema, Mapping)
                or set(schema) != {"version", "build", "selected_schema"}
                or type(schema["version"]) is not str or schema["version"] != "v7.0.0"
                or type(schema["build"]) is not int or schema["build"] != 29):
            raise ValueError
        selected = schema["selected_schema"]
        if not isinstance(selected, Mapping) or set(selected) != {FIELD}:
            raise ValueError
        field = selected[FIELD]
        if (not isinstance(field, Mapping) or set(field) != set(expected)
                or any(type(field[key]) is not type(value) or field[key] != value
                       for key, value in expected.items())):
            raise ValueError
    except Exception:
        raise SecretInstructionBuild29ContractError(_ERROR) from None


def _association(payload: object, identity: Mapping[str, object]) -> str:
    if set(identity) != _IDENTITY:
        raise ValueError
    for key in ("id", "folder"):
        number = identity[key]
        if type(number) is not int or not 0 < number <= 2_147_483_647:
            raise ValueError
    for key in ("name", "template"):
        value = identity[key]
        if type(value) is not str:
            raise ValueError
        _bounded_name(value, maximum=255 if key == "name" else 79)
    if (not isinstance(payload, Mapping) or set(payload) != {"version", "build", "results"}
            or type(payload["version"]) is not str or payload["version"] != "v7.0.0"
            or type(payload["build"]) is not int or payload["build"] != 29):
        raise ValueError
    row = payload["results"]
    if (not isinstance(row, Mapping) or set(row) != _IDENTITY | {FIELD}
            or any(type(row[key]) is not type(identity[key]) or row[key] != identity[key]
                   for key in _IDENTITY) or type(row[FIELD]) is not str):
        raise ValueError
    return str(row[FIELD])


def compile_secret_instruction_build29_attach_body(
    baseline: object, *, schema: object, identity: Mapping[str, object],
    instruction_profile_name: str,
) -> dict[str, str]:
    """Compile from an explicitly unassigned Secret to one typed lab Profile.

    The caller must independently establish both objects and their ownership.
    Neither a valid name nor these metadata values grant that authority.
    """
    try:
        qualify_secret_instruction_build29_schema(schema)
        if (type(instruction_profile_name) is not str
                or _NAME.fullmatch(instruction_profile_name) is None
                or _association(baseline, identity) != ""):
            raise ValueError
        return {FIELD: instruction_profile_name}
    except Exception:
        raise SecretInstructionBuild29ContractError(_ERROR) from None


def compile_secret_instruction_build29_restore_body(
    applied: object, baseline: object, *, schema: object,
    identity: Mapping[str, object], instruction_profile_name: str,
) -> dict[str, str]:
    """Compile only the original empty reference, from the exact applied state."""
    try:
        expected = compile_secret_instruction_build29_attach_body(
            baseline, schema=schema, identity=identity,
            instruction_profile_name=instruction_profile_name,
        )
        if _association(applied, identity) != expected[FIELD]:
            raise ValueError
        return {FIELD: ""}
    except Exception:
        raise SecretInstructionBuild29ContractError(_ERROR) from None
