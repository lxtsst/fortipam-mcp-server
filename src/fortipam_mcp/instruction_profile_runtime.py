"""Default-closed owner startup for independently authorized Instruction Profile phases.

Startup validates owner-only manifests and original creation records for deletion
without a device request. Each phase pins distinct keys and an M4 ledger.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, cast

from v4_planning.models import require_digest, require_ref

from .instruction_profile_contract import (
    InstructionDocument, InstructionHttpsLink, InstructionNode, InstructionPlainText,
    InstructionProfileCreatePlan, InstructionRichText,
)
from .ldap_server_projection import _array, _members, _validate
from .ldap_server_runtime import _decode, _key, _path, _private_file, _read
from .instruction_profile_http_transport import FortiPamInstructionProfileHttpTransport, Phase
from .instruction_profile_live_workflow import InstructionProfileLiveWorkflow
from .instruction_profile_mcp_action import InstructionProfileMcpAction
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import (
    _json_value_end, _skip_json_space,
    _zeroize_mutable, load_secret_metadata_http_transport_config,
)

PREFIX = "FORTIPAM_MCP_V4_INSTRUCTION_PROFILE_700_"
CONTRACT = "fortipam-v4-instruction-profile-startup-v1"
RICH_CONTRACT = "fortipam-v4-instruction-profile-rich-structure-startup-v2"
_UNAVAILABLE = "FortiPAM Instruction Profile startup is unavailable."
_PATH_KEYS = frozenset({"state_directory",
    "execution_database_file", "execution_hmac_key_file", "authority_hmac_key_file"})
_SCHEMA = {
    "binding": frozenset({"name", "brief", "text", "nonce"}),
    "identity": frozenset({"environment_ref", "scope_ref", "audience_ref", "allowed_requester_digest",
        "allowed_transport_digest", "serial_digest", "schema_digest"}),
    "paths": _PATH_KEYS,
}
_COMMON_MARKER = "instruction-runtime.namespace.json"


def _flag(environment: Mapping[str, str], suffix: str) -> bool:
    value = environment.get(PREFIX + suffix, "false")
    if type(value) is not str or value not in {"true", "false"}:
        raise ValueError
    return value == "true"


def _validate_rich_tokens(raw: bytearray, span: tuple[int, int]) -> None:
    """Bound node depth before decoding, independently of JSON container depth."""
    stack = [(child, 1) for child in _array(raw, span)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if depth > 11 or count + len(stack) > 511:
            raise ValueError
        fields = _members(raw, node)
        if ("kind" not in fields or not set(fields) <= {"kind", "text", "marks", "children", "level", "order", "link"}):
            raise ValueError
        for key, child in fields.items():
            if key == "children":
                stack.extend((entry, depth + 1) for entry in _array(raw, child))
            else:
                _validate(raw, child)


def _manifest(path: Path) -> dict[str, Any]:
    raw = _read(path, 32768)
    try:
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        fields = _members(raw, (start, end))
        if set(fields) != set(_SCHEMA) | {"contract", "phase"}:
            raise ValueError
        _validate(raw, fields["contract"])
        contract = json.loads(raw[slice(*fields["contract"])])
        if type(contract) is not str or contract not in {CONTRACT, RICH_CONTRACT}:
            raise ValueError
        for name, (left, right) in fields.items():
            if name in {"contract", "phase"}:
                if raw[left] != 34:
                    raise ValueError
                _validate(raw, (left, right))
                continue
            children = _members(raw, (left, right))
            expected = _SCHEMA[name]
            if name == "binding" and contract == RICH_CONTRACT:
                expected = frozenset({"name", "brief", "blocks", "nonce"})
            if (set(children) != expected
                    or any(raw[a] != (91 if name == "binding" and key == "blocks" else 34)
                           for key, (a, _) in children.items())):
                raise ValueError
            for key, span in children.items():
                if name == "binding" and key == "blocks":
                    _validate_rich_tokens(raw, span)
                else:
                    _validate(raw, span)
        result = _decode(bytes(raw))
        if result["phase"] not in {"create", "delete"}:
            raise ValueError
        return result
    finally:
        _zeroize_mutable(raw)


def _rich_node(value: object, depth: int = 1) -> InstructionNode:
    # This is a private owner-manifest DSL, never arbitrary ProseMirror JSON or
    # an MCP input. Unknown fields must not be silently discarded by the schema.
    if type(value) is not dict or depth > 11:
        raise ValueError
    kind = value.get("kind")
    allowed = {"kind"}
    if kind == "text":
        allowed |= {"text", "marks", "link"}
        if type(value.get("text")) is not str:
            raise ValueError
    elif kind in {"paragraph", "heading", "bullet_list", "ordered_list", "list_item", "blockquote", "code_block"}:
        allowed.add("children")
        if kind in {"heading", "ordered_list"}:
            allowed.add("level" if kind == "heading" else "order")
    elif kind not in {"hard_break", "horizontal_rule"}:
        raise ValueError
    if not set(value) <= allowed:
        raise ValueError
    children, marks = value.get("children", []), value.get("marks", [])
    if (type(children) is not list or len(children) > 512
            or type(marks) is not list or len(marks) > 3
            or any(type(value[key]) is not int for key in ("level", "order") if key in value)):
        raise ValueError
    link = None
    if "link" in value:
        reference = value["link"]
        if (type(reference) is not dict or "href" not in reference
                or not set(reference) <= {"href", "title"}
                or type(reference["href"]) is not str
                or ("title" in reference and type(reference["title"]) is not str)):
            raise ValueError
        link = InstructionHttpsLink(reference["href"], reference.get("title"))
    return InstructionNode(kind, children=tuple(_rich_node(child, depth + 1) for child in children),
        text=value.get("text"), marks=tuple(marks), level=value.get("level"), order=value.get("order"), link=link)


def _content(manifest: dict[str, Any]) -> InstructionPlainText | InstructionRichText:
    binding = manifest["binding"]
    if manifest["contract"] == CONTRACT:
        return InstructionPlainText(binding["brief"], binding["text"])
    blocks = binding["blocks"]
    if type(blocks) is not list or not 0 < len(blocks) < 512:
        raise ValueError
    return InstructionRichText(binding["brief"], InstructionDocument(tuple(_rich_node(block) for block in blocks)))


def _database_family(database: Path) -> set[Path]:
    return {Path(str(database) + suffix) for suffix in ("", "-wal", "-shm", "-journal")}


def _paths(manifest: dict[str, Any], manifest_path: Path) -> dict[str, Path]:
    paths = {name: _path(value, directory=name.endswith("state_directory"))
             for name, value in manifest["paths"].items()}
    protected = [manifest_path, *paths.values()]
    state = paths["state_directory"]
    if (len(set(protected)) != len(protected)
            or any(state in item.parents for item in protected if item != state)):
        raise ValueError
    database = paths["execution_database_file"]
    family = _database_family(database)
    if (family - {database}) & set(protected):
        raise ValueError
    for member in family:
        if os.path.lexists(member):
            _private_file(member)
    return paths


def _digest(value: object) -> str:
    return hashlib.sha256(b"instruction-profile-startup-pin-v1\x00" + json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()


def _phase_marker(phase: str) -> str:
    return f"instruction-runtime.{phase}.namespace.json"


def _phase_state(phase: str) -> tuple[str, ...]:
    return (f"{phase}.claim.json", f"{phase}-response.json", f"{phase}-ack.json", "created.json" if phase == "create" else "deleted.json")


def _pin(transport: FortiPamInstructionProfileHttpTransport, marker: str, value: dict[str, object]) -> None:
    if not os.path.lexists(transport._directory / marker):
        try:
            transport._write_once(marker, value)
        except FileExistsError:
            pass
    if transport._read(marker) != value:
        raise ValueError


def _pin_namespace(transport: FortiPamInstructionProfileHttpTransport, manifest: dict[str, Any],
                   paths: dict[str, Path], keys: dict[str, bytes]) -> None:
    phase = manifest["phase"]
    plan = transport._plan(initialize=phase == "create")
    if phase == "delete":
        transport._anchors()
        if not os.path.lexists(transport._directory / _phase_marker("create")):
            raise ValueError
    common: dict[str, object] = {"contract": manifest["contract"], "digest": _digest({
        "transport_namespace": transport._namespace, "state_plan_digest": _digest(plan),
    })}
    all_state = (*_phase_state("create"), *_phase_state("delete"),
                 _phase_marker("create"), _phase_marker("delete"))
    if (not os.path.lexists(transport._directory / _COMMON_MARKER)
            and any(os.path.lexists(transport._directory / name) for name in all_state)):
        raise ValueError
    for stored_phase in ("create", "delete"):
        if (any(os.path.lexists(transport._directory / name) for name in _phase_state(stored_phase))
                and not os.path.lexists(transport._directory / _phase_marker(stored_phase))):
            raise ValueError
    family = _database_family(paths["execution_database_file"])
    database_digests = sorted(_digest(str(path)) for path in family)
    key_digests = sorted(hashlib.sha256(key).hexdigest() for key in keys.values())
    key_path_digests = sorted(_digest(str(paths[name + "_hmac_key_file"])) for name in keys)
    marker = _phase_marker(phase)
    phase_pin = {"contract": manifest["contract"], "phase": phase, "common_digest": common["digest"],
        "database_family_digests": database_digests, "key_digests": key_digests,
        "key_path_digests": key_path_digests,
        "digest": hmac.new(keys["authority"], b"instruction-profile-phase-namespace-v1\x00" +
            json.dumps({"manifest": manifest, "keys": key_digests}, sort_keys=True,
                       separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()}
    other_marker = _phase_marker("delete" if phase == "create" else "create")
    if os.path.lexists(transport._directory / other_marker):
        other = transport._read(other_marker)
        if (set(other) != set(phase_pin) or other["contract"] != manifest["contract"]
                or other["phase"] != ("delete" if phase == "create" else "create")
                or other["common_digest"] != common["digest"]):
            raise ValueError
        validated: dict[str, set[str]] = {}
        for name, count in (("database_family_digests", 4), ("key_digests", 2), ("key_path_digests", 2)):
            values = other[name]
            if (type(values) is not list or len(values) != count
                    or any(type(value) is not str for value in values)):
                raise ValueError
            for value in values:
                require_digest(value, name)
            if len(set(values)) != count:
                raise ValueError
            validated[name] = set(values)
        other_digest = other["digest"]
        if type(other_digest) is not str:
            raise ValueError
        require_digest(other_digest, "phase namespace digest")
        if (set(database_digests).intersection(validated["database_family_digests"])
                or set(key_digests).intersection(validated["key_digests"])
                or set(key_path_digests).intersection(validated["key_path_digests"])):
            raise ValueError
    if not os.path.lexists(transport._directory / marker):
        phase_state = _phase_state(phase)
        if (any(os.path.lexists(transport._directory / name) for name in phase_state)
                or any(os.path.lexists(path) for path in family)):
            raise ValueError
    elif not paths["execution_database_file"].exists():
        # M4 can consume a claim before the transport creates an HTTP marker.
        # A pinned phase must never recreate its missing ledger automatically.
        raise ValueError
    _pin(transport, _COMMON_MARKER, common)
    _pin(transport, marker, phase_pin)


def build_instruction_profile_candidate(environment: Mapping[str, str]) -> InstructionProfileMcpAction | None:
    """Compose one fixed phase; disabled startup returns before any file I/O."""
    try:
        enabled, execution = _flag(environment, "ENABLED"), _flag(environment, "EXECUTION_ENABLED")
        if not enabled:
            if execution:
                raise ValueError
            return None
        manifest_path = _path(environment[PREFIX + "STARTUP_MANIFEST_FILE"])
        manifest = _manifest(manifest_path)
        paths = _paths(manifest, manifest_path)
        identity = manifest["identity"]
        content = _content(manifest)
        binding = InstructionProfileCreatePlan(manifest["binding"]["name"], manifest["binding"]["nonce"],
            content, {"name": "", "brief": "", "detail": ""},
            schema_digest=identity["schema_digest"], serial_digest=identity["serial_digest"])
        for name in ("environment_ref", "scope_ref", "audience_ref"):
            require_ref(identity[name], name)
        for name in ("allowed_requester_digest", "allowed_transport_digest", "serial_digest", "schema_digest"):
            require_digest(identity[name], name)
        keys = {name: _key(paths[name + "_hmac_key_file"]) for name in ("authority", "execution")}
        if len(set(keys.values())) != 2:
            raise ValueError
        config = load_secret_metadata_http_transport_config(environment)
        transport = FortiPamInstructionProfileHttpTransport(config, binding,
            serial_digest=identity["serial_digest"], schema_digest=identity["schema_digest"],
            state_directory=paths["state_directory"], phase=cast(Phase, manifest["phase"]))
        with transport.operation_lock():
            _pin_namespace(transport, manifest, paths, keys)
            execution_store = PersistentM4ExecutionStateStore(
                paths["execution_database_file"], paths["execution_hmac_key_file"])
        workflow = InstructionProfileLiveWorkflow(binding, config,
            state_directory=paths["state_directory"], phase=manifest["phase"],
            execution_store=execution_store, authority_key=keys["authority"],
            execution_enabled=execution, **identity)
        return InstructionProfileMcpAction(workflow, execution_enabled=execution)
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


__all__ = ["build_instruction_profile_candidate"]
