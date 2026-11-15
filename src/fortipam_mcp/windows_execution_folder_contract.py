"""Pure build29 explicit-Policy owner-only Folder candidate.

This does not extend the inherited 3.3 Folder action, establish ownership, open
a Gate or provide I/O. An original Policy custody object and current references
must still be joined by the future trusted producer before any dispatch.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as m
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _zeroize_mutable
from .target_lifecycle_dependencies import _envelope, _one, _spans
from .target_preservation_contract import _digest, _token_digest
from .windows_execution_policy_contract import (
    CANONICAL_PROFILE, WindowsExecutionPolicyRequest, consume_windows_policy_state,
)

CONTRACT = "fortipam-build29-explicit-policy-windows-folder-private-v1"
FIELDS = frozenset({"id", "name", "parent-folder", "folder-type", "inherit-policy", "secret-policy",
    "inherit-permission", "inherit-folder-ztna", "ztna-tags-match-logic", "ztna-ems-tag",
    "user-permission", "group-permission"})
WIRE_FIELDS = FIELDS - {"folder-type"}
_ERROR = "The private explicit-Policy Windows Folder contract is unavailable."
_NAME = re.compile(r"mcp-v4-winexec-explicit-[0-9]{8}-r[1-9][0-9]{0,3}\Z")
_OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}\Z")


class WindowsExecutionFolderError(ValueError):
    """Non-disclosing refusal, without adoption or recovery authority."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsFolderNativeAcknowledgement(_OpaqueC3Object):
    native_folder_id: int
    native_status: str
    response_digest: str


def consume_windows_execution_folder_ack(raw: bytearray, *, request: WindowsExecutionFolderRequest,
        phase: str, http_status: int, native_folder_id: int | None = None) -> WindowsFolderNativeAcknowledgement:
    """First-source private ACK profile; record the actual native success label.

    Both recognized CMDB success labels are explicit source-observation grammar,
    as in the existing Web ACK source qualifier. No public execution profile is
    promoted by observing one. Every other envelope/route/ID guard stays exact.
    """
    try:
        request.validate()
        if (phase not in ("create", "delete") or type(http_status) is not int or http_status != 200
                or phase == "create" and native_folder_id is not None
                or phase == "delete" and not _positive(native_folder_id)):
            raise ValueError
        fields = _spans(raw)
        outer = _object_spans(raw, 0, len(raw))
        wanted = {"version":"v7.0.0", "build":29, "http_method":"POST" if phase == "create" else "DELETE",
            "http_status":200, "path":"secret", "name":"folder", "vdom":"root"}
        for key, value in wanted.items():
            actual = m._scalar(raw, fields[key])
            if type(actual) is not type(value) or actual != value:
                raise ValueError
        status = m._scalar(raw, fields["status"])
        serial = m._scalar(raw, fields["serial"])
        identifier = m._scalar(raw, fields["mkey"])
        if (type(status) is not str or status not in ("OK", "success")
                or type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != request.binding.policy_request.binding.serial_digest
                or not _positive(identifier) or phase == "delete" and identifier != native_folder_id
                or "schema_errors" in outer
                or "action" in outer and m._scalar(raw, outer["action"]) != ""
                or "error" in fields and (type(m._scalar(raw, fields["error"])) is not int or m._scalar(raw, fields["error"]) != 0)):
            raise ValueError
        assert isinstance(identifier, int)
        return WindowsFolderNativeAcknowledgement(identifier, status, hashlib.sha256(raw).hexdigest())
    except Exception:
        raise WindowsExecutionFolderError(_ERROR) from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


@dataclass(frozen=True, slots=True, repr=False)
class WindowsExecutionFolderBinding(_OpaqueC3Object):
    name: str
    parent_folder_id: int
    owner_name: str
    parent_digest: str
    policy_request: WindowsExecutionPolicyRequest
    policy_custody_digest: str
    policy_state_digest: str
    policy_source_context_digest: str

    def validate(self) -> None:
        try:
            if (type(self.name) is not str or _NAME.fullmatch(self.name) is None
                    or not _positive(self.parent_folder_id)
                    or type(self.owner_name) is not str or _OWNER.fullmatch(self.owner_name) is None
                    or type(self.policy_request) is not WindowsExecutionPolicyRequest):
                raise ValueError
            self.policy_request.validate()
            if self.policy_request.profile != CANONICAL_PROFILE:
                raise ValueError
            for value in (self.parent_digest, self.policy_custody_digest, self.policy_state_digest,
                          self.policy_source_context_digest):
                require_digest(value, "folder_dependency")
        except Exception:
            raise WindowsExecutionFolderError(_ERROR) from None

    @property
    def digest(self) -> str:
        self.validate()
        return _digest((CONTRACT, self.name, self.parent_folder_id, self.owner_name, self.parent_digest,
            self.policy_request.request_digest, self.policy_custody_digest, self.policy_state_digest,
            self.policy_source_context_digest))


def _positive(value: object) -> bool:
    return type(value) is int and 0 < value <= 2147483647


def _encode(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _defaults(values: object) -> dict[str, object]:
    if type(values) is not dict or set(values) != FIELDS:
        raise ValueError
    fixed = {"id":0, "name":"", "parent-folder":0, "folder-type":"public", "secret-policy":"",
        "inherit-policy":"enable", "inherit-permission":"enable", "inherit-folder-ztna":"enable",
        "user-permission":[], "group-permission":[], "ztna-ems-tag":[]}
    if (any(type(values[key]) is not type(value) or values[key] != value for key, value in fixed.items())
            or type(values["ztna-tags-match-logic"]) is not str or values["ztna-tags-match-logic"] not in ("and", "or")):
        raise ValueError
    return values


def _body(binding: WindowsExecutionFolderBinding, defaults: dict[str, object]) -> dict[str, object]:
    return {"id":0, "name":binding.name, "parent-folder":binding.parent_folder_id,
        "inherit-policy":"disable", "secret-policy":binding.policy_request.binding.name,
        "inherit-permission":"disable", "inherit-folder-ztna":"enable",
        "ztna-tags-match-logic":defaults["ztna-tags-match-logic"], "ztna-ems-tag":[],
        "user-permission":[{"id":0, "user-name":[{"name":binding.owner_name}],
            "folder-permission":"owner", "secret-permission":"owner", "allowed-launcher-type":"all"}],
        "group-permission":[]}


@dataclass(frozen=True, slots=True, repr=False)
class WindowsExecutionFolderRequest(_OpaqueC3Object):
    binding: WindowsExecutionFolderBinding
    schema_digest: str
    defaults_digest: str
    defaults_json: str
    body_json: str
    body_digest: str
    expected_state_digest: str
    request_digest: str

    def validate(self) -> None:
        try:
            if type(self.binding) is not WindowsExecutionFolderBinding:
                raise ValueError
            self.binding.validate()
            for value in (self.schema_digest, self.defaults_digest, self.body_digest,
                          self.expected_state_digest, self.request_digest):
                require_digest(value, "folder_request")
            if (type(self.defaults_json) is not str or len(self.defaults_json) > 16384
                    or type(self.body_json) is not str or len(self.body_json) > 16384):
                raise ValueError
            defaults = _defaults(json.loads(self.defaults_json))
            if (json.dumps(defaults, ensure_ascii=True, separators=(",", ":"), allow_nan=False) != self.defaults_json
                    or hashlib.sha256(self.defaults_json.encode()).hexdigest() != self.defaults_digest
                    or _encode(_body(self.binding, defaults)) != self.body_json
                    or hashlib.sha256(self.body_json.encode()).hexdigest() != self.body_digest
                    or self.expected_state_digest != _expected(self.binding, self.body_digest)
                    or self.request_digest != _request(self.binding, self.schema_digest, self.defaults_digest,
                        self.body_digest, self.expected_state_digest)):
                raise ValueError
        except Exception:
            raise WindowsExecutionFolderError(_ERROR) from None


def _expected(binding: WindowsExecutionFolderBinding, body: str) -> str:
    # The original ACK supplies the new native ID. Its new Owner relation ID
    # must be positive; both allocations are subsequently pinned by the full seal.
    return _digest((CONTRACT, binding.digest, body, "public", "original-ack-folder-id",
        "new-positive-owner-relation-id", "permissions-user-owner", "complete-fourteen-field-state"))


def _request(binding: WindowsExecutionFolderBinding, schema: str, defaults: str, body: str, expected: str) -> str:
    return _digest((CONTRACT, binding.digest, schema, defaults, body, expected,
        "POST", "/api/v2/cmdb/secret/folder"))


def _descriptor(raw: bytearray, span: tuple[int, int], *, kind: str | None,
        key: str | None = None, children: dict[str, object] | None = None) -> None:
    props = _object_spans(raw, *span)
    if any(m._scalar(raw, props[flag]) is not False for flag in ("readonly", "read_only", "read-only") if flag in props):
        raise ValueError
    if kind is not None:
        if "type" not in props or m._scalar(raw, props["type"]) != kind or "children" in props or "mkey" in props:
            raise ValueError
    else:
        if "type" in props or "mkey" not in props or m._scalar(raw, props["mkey"]) != key or children is None:
            raise ValueError
        fields = _object_spans(raw, *props["children"])
        if set(fields) != set(children):
            raise ValueError
        for name, spec in children.items():
            if type(spec) is str:
                _descriptor(raw, fields[name], kind=spec)
            elif type(spec) is dict:
                _descriptor(raw, fields[name], kind=None, key="name", children=spec)
            else:
                raise ValueError


def compile_windows_execution_folder(schema: bytearray, defaults: bytearray, *,
        binding: WindowsExecutionFolderBinding) -> WindowsExecutionFolderRequest:
    """Consume complete native schema/defaults; return a draft, not authority."""
    try:
        if type(binding) is not WindowsExecutionFolderBinding:
            raise ValueError
        binding.validate()
        serial = binding.policy_request.binding.serial_digest
        for raw in (schema, defaults):
            _spans(raw)
            if "schema_errors" in _object_spans(raw, 0, len(raw)):
                raise ValueError
        row = _one(schema, _envelope(schema, path="secret", name="folder", serial_digest=serial, action="schema"))
        props = m._object_spans(schema, *row, frozenset({"children"}))
        fields = _object_spans(schema, *props["children"])
        if set(fields) != FIELDS:
            raise ValueError
        for key, span in fields.items():
            if key in ("user-permission", "group-permission"):
                principal = "user-name" if key == "user-permission" else "group-name"
                _descriptor(schema, span, kind=None, key="id", children={"id":"integer",
                    principal:{"name":"string"}, "folder-permission":"option", "secret-permission":"option",
                    "allowed-launcher-type":"option"})
            elif key == "ztna-ems-tag":
                _descriptor(schema, span, kind=None, key="name", children={"name":"string"})
            else:
                _descriptor(schema, span, kind="integer" if key in ("id", "parent-folder")
                    else "string" if key in ("name", "secret-policy") else "option")
        schema_digest = _token_digest(schema, row)
        row = _one(defaults, _envelope(defaults, path="secret", name="folder", serial_digest=serial, action="default"))
        fields = _object_spans(defaults, *row)
        values = _defaults({key:json.loads(defaults[slice(*span)]) for key, span in fields.items()})
        defaults_digest = _token_digest(defaults, row)
        defaults_json = json.dumps(values, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        body_json = _encode(_body(binding, values))
        body_digest = hashlib.sha256(body_json.encode()).hexdigest()
        expected = _expected(binding, body_digest)
        request = WindowsExecutionFolderRequest(binding, schema_digest, defaults_digest, defaults_json,
            body_json, body_digest, expected, _request(binding, schema_digest, defaults_digest, body_digest, expected))
        request.validate()
        return request
    except Exception:
        raise WindowsExecutionFolderError(_ERROR) from None
    finally:
        for raw in (schema, defaults):
            if type(raw) is bytearray:
                _zeroize_mutable(raw)


def _folder_detail_columns(raw: bytearray, *, serial_digest: str,
        native_folder_id: int) -> dict[str, tuple[int, int]]:
    """Fixed Folder detail framing shared by candidate and exact parent reads."""
    if not _positive(native_folder_id):
        raise ValueError
    fields = _spans(raw)
    wanted = {"version":"v7.0.0", "build":29, "http_method":"GET", "http_status":200,
        "status":"OK", "path":"secret", "name":"folder", "vdom":"root"}
    for key, value in wanted.items():
        actual = m._scalar(raw, fields[key])
        if type(actual) is not type(value) or actual != value:
            raise ValueError
    serial = m._scalar(raw, fields["serial"])
    if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != serial_digest:
        raise ValueError
    outer = _object_spans(raw, 0, len(raw))
    if "schema_errors" in outer or "action" in outer and m._scalar(raw, outer["action"]) != "":
        raise ValueError
    if "error" in fields and (type(m._scalar(raw, fields["error"])) is not int or m._scalar(raw, fields["error"]) != 0):
        raise ValueError
    if "mkey" in fields:
        native_key = m._scalar(raw, fields["mkey"])
        if type(native_key) not in (int, str) or native_key not in (native_folder_id, str(native_folder_id)):
            raise ValueError
    if ("limit_reached" in fields and m._scalar(raw, fields["limit_reached"]) is not False
            or any(key in outer for key in ("next_idx", "next_index", "total", "total_count"))
            or any(type(m._scalar(raw, outer[key])) is not int or m._scalar(raw, outer[key]) != 1
                for key in ("size", "matched_count") if key in outer)):
        raise ValueError
    row = _one(raw, fields["results"])
    columns = _object_spans(raw, *row)
    if set(columns) != FIELDS | {"q_origin_key", "permissions"}:
        raise ValueError
    for key in ("id", "q_origin_key"):
        value = m._scalar(raw, columns[key])
        if type(value) is not int or value != native_folder_id:
            raise ValueError
    return columns


def consume_windows_execution_folder_state(raw: bytearray, *, request: WindowsExecutionFolderRequest,
        native_folder_id: int) -> str:
    """Qualify all14 fields; the original ACK and producer supply provenance."""
    try:
        request.validate()
        columns = _folder_detail_columns(raw, serial_digest=request.binding.policy_request.binding.serial_digest,
            native_folder_id=native_folder_id)
        values = {key:json.loads(raw[slice(*span)]) for key, span in columns.items()}
        body = json.loads(request.body_json)
        expected = {**body, "id":native_folder_id, "folder-type":"public",
            "q_origin_key":native_folder_id, "permissions":{"user":"owner"}}
        for key in expected.keys() - {"user-permission"}:
            if type(values[key]) is not type(expected[key]) or values[key] != expected[key]:
                raise ValueError
        users = values["user-permission"]
        if type(users) is not list or len(users) != 1 or type(users[0]) is not dict:
            raise ValueError
        relation = users[0]
        if (not set(body["user-permission"][0]) <= set(relation)
                or not set(relation) <= set(body["user-permission"][0]) | {"q_origin_key"}
                or not _positive(relation["id"])
                or "q_origin_key" in relation and (type(relation["q_origin_key"]) is not int or relation["q_origin_key"] != relation["id"])):
            raise ValueError
        for key in ("folder-permission", "secret-permission", "allowed-launcher-type"):
            if relation[key] != body["user-permission"][0][key]:
                raise ValueError
        principals = relation["user-name"]
        if (type(principals) is not list or len(principals) != 1 or type(principals[0]) is not dict
                or not {"name"} <= set(principals[0]) <= {"name", "q_origin_key"}
                or principals[0]["name"] != request.binding.owner_name
                or "q_origin_key" in principals[0] and principals[0]["q_origin_key"] != request.binding.owner_name):
            raise ValueError
        return _digest((CONTRACT, request.request_digest, values))
    except Exception:
        raise WindowsExecutionFolderError(_ERROR) from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


def consume_windows_execution_policy_link(raw: bytearray, *, binding: WindowsExecutionFolderBinding,
        expected_references: int) -> str:
    """Require the original full Policy, permitting only its exact0/1 ref delta.

    A future live source must additionally prove the actual original custody,
    current global CLI count and original Folder relationship for that phase.
    """
    normalized = bytearray()
    try:
        binding.validate()
        if type(expected_references) is not int or expected_references not in (0, 1):
            raise ValueError
        row = _one(raw, _envelope(raw, path="secret", name="policy",
            serial_digest=binding.policy_request.binding.serial_digest))
        fields = _object_spans(raw, *row)
        value = m._scalar(raw, fields["q_ref"])
        if type(value) is not int or value != expected_references:
            raise ValueError
        left, right = fields["q_ref"]
        normalized = raw[:left] + b"0" + raw[right:]
        fingerprint = consume_windows_policy_state(normalized, request=binding.policy_request)
        if fingerprint != binding.policy_state_digest:
            raise ValueError
        return _digest((CONTRACT, binding.digest, "original-policy-reference", expected_references, fingerprint))
    except Exception:
        raise WindowsExecutionFolderError(_ERROR) from None
    finally:
        for content in (raw, normalized):
            if type(content) is bytearray:
                _zeroize_mutable(content)
