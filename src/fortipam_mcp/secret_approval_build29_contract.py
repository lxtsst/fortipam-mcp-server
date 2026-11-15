"""Pure, unregistered build-29 four-field approval transition candidate.

Schema qualification and body compilation confer no dispatch authority. These
functions do not prove partial PUT persistence, full-Secret preservation, live
permissions, or restoration acceptance. Metadata input is only a minimized
redacted projection {version, build, results}; a future independently qualified
producer must establish its provenance. Schema proof does not qualify the
Secret detail HTTP envelope or that producer. Selectors and bodies stay private.
"""

from collections.abc import Mapping
import re


CONTRACT = "fortipam-700-build29-secret-approval-transition-candidate-v1"
APPROVAL_FIELDS = frozenset({
    "need-approval", "need-approval-job", "bypass-approval", "approval-profile",
})
_IDENTITY = frozenset({"id", "name", "folder"})
_BASELINE = {
    "need-approval": "disable", "need-approval-job": "disable",
    "bypass-approval": "disable", "approval-profile": "",
}
_ENVELOPE = {"version": "v7.0.0", "build": 29}
_UNAVAILABLE = "The fixed build-29 Secret approval transition is unavailable."


class SecretApprovalBuild29ContractError(ValueError):
    """Stable rejection without source contents or protected selectors."""


def qualify_secret_approval_build29_schema(schema: object) -> None:
    """Require the exact minimized source shape and approval semantics."""
    try:
        if (not isinstance(schema, Mapping)
                or set(schema) != {"version", "build", "selected_schema"}
                or type(schema.get("version")) is not str
                or schema["version"] != "v7.0.0"
                or type(schema.get("build")) is not int or schema["build"] != 29):
            raise ValueError
        selected = schema["selected_schema"]
        if not isinstance(selected, Mapping) or set(selected) != APPROVAL_FIELDS:
            raise ValueError
        for name in APPROVAL_FIELDS:
            member = selected[name]
            expected = {
                "name": name, "category": "unitary", "multiple_values": False,
                "default": _BASELINE[name],
                "type": "string" if name == "approval-profile" else "option",
            }
            if name != "bypass-approval":
                expected["required"] = True
            keys = set(expected) | {"help"}
            keys |= {"size", "datasource"} if name == "approval-profile" else {"options"}
            if (not isinstance(member, Mapping) or set(member) != keys
                    or type(member.get("help")) is not str
                    or any(type(member.get(key)) is not type(value)
                           or member[key] != value for key, value in expected.items())):
                raise ValueError
            if name == "approval-profile":
                if (type(member["size"]) is not int or member["size"] != 79
                        or type(member["datasource"]) is not list
                        or member["datasource"] != ["secret.approval-profile.name"]):
                    raise ValueError
            else:
                options = member["options"]
                if (type(options) is not list or len(options) != 2
                        or any(not isinstance(option, Mapping)
                               or set(option) != {"name", "help"}
                               or type(option.get("name")) is not str
                               or option["name"] != value
                               or type(option.get("help")) is not str
                               for option, value in zip(options, ("enable", "disable")))):
                    raise ValueError
    except Exception:
        raise SecretApprovalBuild29ContractError(_UNAVAILABLE) from None


def compile_secret_approval_build29_enable_body(
    baseline: object, *, schema: object, identity: Mapping[str, object],
    approval_profile_name: str,
) -> dict[str, str]:
    """Compile from disabled approvals and empty profile, retaining bypass state.

    The caller must independently verify the existing Profile. A bounded name
    and its schema datasource do not establish Profile existence or semantics.
    """
    try:
        qualify_secret_approval_build29_schema(schema)
        _validate_binding(identity, approval_profile_name)
        original = _approval_fields(baseline, identity)
        if any(original[key] != value for key, value in _BASELINE.items()
               if key != "bypass-approval"):
            raise ValueError
        return _applied_fields(approval_profile_name, original["bypass-approval"])
    except Exception:
        raise SecretApprovalBuild29ContractError(_UNAVAILABLE) from None


def compile_secret_approval_build29_restore_body(
    applied: object, baseline: object, *, schema: object,
    identity: Mapping[str, object], approval_profile_name: str,
) -> dict[str, str]:
    """Restore the preserved four fields only from the same bound applied tuple."""
    try:
        expected = compile_secret_approval_build29_enable_body(
            baseline, schema=schema, identity=identity,
            approval_profile_name=approval_profile_name,
        )
        if _approval_fields(applied, identity) != expected:
            raise ValueError
        return _approval_fields(baseline, identity)
    except Exception:
        raise SecretApprovalBuild29ContractError(_UNAVAILABLE) from None


def _validate_binding(identity: Mapping[str, object], profile: str) -> None:
    if not isinstance(identity, Mapping) or set(identity) != _IDENTITY:
        raise ValueError
    for key in ("id", "folder"):
        number = identity[key]
        if type(number) is not int or not 0 < number <= 2_147_483_647:
            raise ValueError
    if (type(identity["name"]) is not str
            or re.fullmatch(r"mcp-v4-[A-Za-z0-9][A-Za-z0-9._-]{0,119}", identity["name"]) is None
            or type(profile) is not str
            or re.fullmatch(r"mcp-v4-approval-profile-[A-Za-z0-9][A-Za-z0-9._-]{0,39}", profile) is None):
        raise ValueError


def _approval_fields(payload: object, identity: Mapping[str, object]) -> dict[str, str]:
    """Validate minimized projection values, without claiming HTTP qualification."""
    if (not isinstance(payload, Mapping) or set(payload) != set(_ENVELOPE) | {"results"}
            or any(type(payload.get(key)) is not type(value) or payload[key] != value
                   for key, value in _ENVELOPE.items())):
        raise ValueError
    row = payload["results"]
    if isinstance(row, list) and len(row) == 1:
        row = row[0]
    required = _IDENTITY | APPROVAL_FIELDS
    if (not isinstance(row, Mapping) or not required.issubset(row)
            or not set(row).issubset(required | {"q_origin_key", "field", "keyinfo"})
            or any(type(row.get(key)) is not type(value) or row[key] != value
                   for key, value in identity.items())
            or row.get("field") is not None or row.get("keyinfo") is not None):
        raise ValueError
    origin = row.get("q_origin_key", identity["id"])
    if type(origin) not in (int, str) or origin not in (identity["id"], str(identity["id"])):
        raise ValueError
    result: dict[str, str] = {}
    for key in APPROVAL_FIELDS:
        value = row[key]
        if type(value) is not str:
            raise ValueError
        if key != "approval-profile" and value not in ("enable", "disable"):
            raise ValueError
        result[key] = value
    return result


def _applied_fields(profile: str, bypass: str) -> dict[str, str]:
    return {**_BASELINE, "need-approval": "enable", "bypass-approval": bypass, "approval-profile": profile}
