"""I/O-free build29 inactive Windows Policy request and evidence candidate.

The original producer must separately qualify permissions, absence, M4 dispatch,
signed original-ACK custody, complete readback and independent recovery. Nothing
here adopts an existing Policy, grants ownership, changes a Gate or exposes a Tool.
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

CONTRACT = "fortipam-build29-inactive-windows-policy-private-v1"
STRICT_PROFILE = "strict-wire-v1"
CANONICAL_PROFILE = "canonical-inactive-v2"
FIELDS = frozenset({
    "name", "password-changer", "password-heartbeat", "checkout", "recording", "need-approval",
    "need-approval-job", "av-scan", "dlp-status", "proxy", "ssh-filter", "ssh-algorithm", "winappfilter",
    "rdp-remote-app", "rdp-remote-app-profile", "rdp-remote-app-owner-exempt", "rdp-security-level",
    "rdp-auto-totp", "rdp-restricted-admin-mode", "block-clipboard", "cert-expiry-log",
    "pwd-chg-sch-frequency", "pwd-chg-sch-interval", "pwd-chg-sch-month-type", "pwd-chg-sch-month-day",
    "pwd-chg-sch-week-day", "pwd-chg-sch-start-date", "heartbeat-interval", "heartbeat-start-time",
    "checkout-duration", "force-checkout-idle-time", "checkin-pwd-change", "checkout-duration-renew",
    "checkout-renew-times", "tunnel-encryption", "secret-auth", "secret-auth-server", "secret-auth-duration",
    "secret-auth-owner-exempt", "bypass-approval", "approval-profile", "ssh-filter-profile",
    "bypass-ssh-filter-for-owner", "winappfilter-profile", "dlp-sensor", "av-profile",
    "pwd-chg-secret-edit", "heartbeat-secret-edit", "rdp-event-filter", "rdp-event-filter-profile",
})
# The native UI omits these backend fields on POST. Preserve their exact fresh
# default values in the expected complete state, never add inferred wire keys.
PRESERVED = frozenset({"credential-expire-notification", "credential-expiry-after",
    "last-credential-change-date", "rdp-nla-kerberos"})
DISABLED = frozenset({
    "password-changer", "password-heartbeat", "pwd-chg-secret-edit", "heartbeat-secret-edit", "checkout",
    "recording", "need-approval", "need-approval-job", "av-scan", "dlp-status", "proxy", "ssh-filter",
    "winappfilter", "checkin-pwd-change", "checkout-duration-renew", "secret-auth", "rdp-event-filter",
    "block-clipboard",
})
_RELATIONS = frozenset({"secret-auth-server", "approval-profile", "ssh-filter-profile", "winappfilter-profile",
    "dlp-sensor", "av-profile", "rdp-event-filter-profile", "rdp-remote-app-profile"})
_INTEGERS = frozenset({"pwd-chg-sch-interval", "heartbeat-interval", "checkout-duration",
    "force-checkout-idle-time", "checkout-renew-times", "secret-auth-duration"})
_DATES = frozenset({"pwd-chg-sch-start-date", "heartbeat-start-time"})
_NORMALIZED: dict[str, str | int] = {
    "pwd-chg-sch-frequency":"unknown", "pwd-chg-sch-interval":0, "pwd-chg-sch-month-type":"unknown",
    "pwd-chg-sch-month-day":"", "pwd-chg-sch-week-day":"", "pwd-chg-sch-start-date":"",
    "heartbeat-start-time":"",
}
_DORMANT_DEFAULTS = frozenset(_NORMALIZED) | {"checkin-pwd-change", "checkout-duration-renew"}
_META = frozenset({"q_origin_key", "q_ref", "q_static", "q_no_edit", "q_no_rename", "q_global_entry",
    "q_type", "q_path", "q_name", "q_mkey_type"})
_NAME = re.compile(r"mcp-v4-secret-policy-winexec-[0-9]{8}-r[1-9][0-9]{0,3}\Z")
_ERROR = "The private inactive Windows Policy contract is unavailable."


class WindowsExecutionPolicyError(ValueError):
    """Non-disclosing refusal; no partial proof or retry authority."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsExecutionPolicyBinding(_OpaqueC3Object):
    name: str
    serial_digest: str

    def __post_init__(self) -> None:
        try:
            if type(self.name) is not str or _NAME.fullmatch(self.name) is None:
                raise ValueError
            require_digest(self.serial_digest, "policy_serial")
        except Exception:
            raise WindowsExecutionPolicyError(_ERROR) from None

    @property
    def digest(self) -> str:
        self.__post_init__()
        return _digest((CONTRACT, self.name, self.serial_digest))


@dataclass(frozen=True, slots=True, repr=False)
class WindowsExecutionPolicyRequest(_OpaqueC3Object):
    binding: WindowsExecutionPolicyBinding
    schema_digest: str
    defaults_digest: str
    body_json: str
    body_digest: str
    expected_state_json: str
    expected_state_digest: str
    request_digest: str
    profile: str = STRICT_PROFILE
    defaults_json: str | None = None

    def validate(self) -> None:
        try:
            self.binding.__post_init__()
            for value in (self.schema_digest, self.defaults_digest, self.body_digest,
                          self.expected_state_digest, self.request_digest):
                require_digest(value, "policy_request")
            if (type(self.body_json) is not str or len(self.body_json) > 32768
                    or hashlib.sha256(self.body_json.encode()).hexdigest() != self.body_digest
                    or self.request_digest != _request_digest(self.binding, self.schema_digest,
                        self.defaults_digest, self.body_digest, self.expected_state_digest,
                        self.profile, self.defaults_json)):
                raise ValueError
            body = json.loads(self.body_json)
            if type(body) is not dict or set(body) != FIELDS | {"$originalName"}:
                raise ValueError
            if json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False) != self.body_json:
                raise ValueError
            _profile(body, self.binding.name)
            if body["$originalName"] != "":
                raise ValueError
            expected = json.loads(self.expected_state_json)
            if (type(expected) is not dict or set(expected) != FIELDS | PRESERVED
                    or _encode(expected) != self.expected_state_json
                    or hashlib.sha256(self.expected_state_json.encode()).hexdigest() != self.expected_state_digest):
                raise ValueError
            _preserved(expected)
            if self.profile == STRICT_PROFILE:
                if self.defaults_json is not None or any(type(expected[key]) is not type(body[key])
                        or expected[key] != body[key] for key in FIELDS):
                    raise ValueError
            elif self.profile == CANONICAL_PROFILE:
                if type(self.defaults_json) is not str or len(self.defaults_json) > 32768:
                    raise ValueError
                native = json.loads(self.defaults_json)
                if (type(native) is not dict
                        or json.dumps(native, ensure_ascii=True, separators=(",", ":"), allow_nan=False) != self.defaults_json
                        or hashlib.sha256(self.defaults_json.encode()).hexdigest() != self.defaults_digest
                        or _canonical_expected(body, native) != expected):
                    raise ValueError
            else:
                raise ValueError
        except Exception:
            raise WindowsExecutionPolicyError(_ERROR) from None


def _request_digest(binding: WindowsExecutionPolicyBinding, schema: str, defaults: str, body: str, expected: str,
        profile: str = STRICT_PROFILE, defaults_json: str | None = None) -> str:
    parts = (CONTRACT, binding.digest, schema, defaults, body, expected,
             "POST", "/api/v2/cmdb/secret/policy", "with_meta=true")
    if profile == STRICT_PROFILE and defaults_json is None:
        return _digest(parts)
    if profile == CANONICAL_PROFILE and type(defaults_json) is str:
        return _digest((*parts, CANONICAL_PROFILE, hashlib.sha256(defaults_json.encode()).hexdigest()))
    raise ValueError


def _values(values: dict[str, object]) -> None:
    for key in FIELDS:
        value = values[key]
        if key in _INTEGERS:
            if type(value) is not int or not 0 <= value <= 2147483647:
                raise ValueError
        elif type(value) is not str or len(value) > 1024 or any(ord(ch) < 32 for ch in value):
            raise ValueError


def _preserved(values: dict[str, object]) -> None:
    for key in ("credential-expire-notification", "rdp-nla-kerberos"):
        value = values[key]
        if type(value) is not str or value not in ("disable", "not-set"):
            raise ValueError
    value = values["credential-expiry-after"]
    if type(value) is not int or not 0 <= value <= 2147483647:
        raise ValueError
    value = values["last-credential-change-date"]
    if type(value) is not str or len(value) > 128 or any(ord(ch) < 32 for ch in value):
        raise ValueError


def _encode(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _profile(values: dict[str, object], name: str) -> None:
    _values(values)
    expected: dict[str, object] = {**dict.fromkeys(DISABLED, "disable"), **dict.fromkeys(_RELATIONS, ""),
        **_NORMALIZED, "name":name}
    if any(type(values[key]) is not type(value) or values[key] != value for key, value in expected.items()):
        raise ValueError


def _canonical_expected(body: dict[str, object], native: dict[str, object]) -> dict[str, object]:
    """Explicit build29 normalization with all owning controls disabled.

    This profile qualifies future original creations only. It cannot repair an
    earlier strict request, acknowledgement, state seal or consumed dispatch.
    """
    if set(native) != FIELDS | PRESERVED:
        raise ValueError
    _values(native)
    _preserved(native)
    if (native["name"] != "" or any(native[key] != "" for key in _RELATIONS)
            or any(native[key] != "not-set" for key in
                ("checkin-pwd-change", "checkout-duration-renew", "rdp-security-level", "rdp-auto-totp"))
            or native["tunnel-encryption"] != "enable"):
        raise ValueError
    wire = {**{key:native[key] for key in FIELDS}, **dict.fromkeys(DISABLED, "disable"), **_NORMALIZED,
            "name":body["name"], "$originalName":""}
    if wire != body:
        raise ValueError
    return {**{key:body[key] for key in FIELDS}, **{key:native[key] for key in PRESERVED | _DORMANT_DEFAULTS},
            "rdp-auto-totp":"disable", "tunnel-encryption":"not-set"}


def compile_windows_execution_policy(schema: bytearray, defaults: bytearray, *,
        binding: WindowsExecutionPolicyBinding, profile: str = STRICT_PROFILE) -> WindowsExecutionPolicyRequest:
    """Consume exact fixed sources, preserve other defaults; no network or authority.

    Fifty wire fields and four backend defaults are required. In particular,
    unsupported UI-only winrm-https must not be supplied or silently dropped.
    """
    try:
        if type(binding) is not WindowsExecutionPolicyBinding:
            raise ValueError
        binding.__post_init__()
        for raw in (schema, defaults):
            _spans(raw)
            if "schema_errors" in _object_spans(raw, 0, len(raw)):
                raise ValueError
        row = _one(schema, _envelope(schema, path="secret", name="policy",
            serial_digest=binding.serial_digest, action="schema"))
        outer = m._object_spans(schema, *row, frozenset({"children"}))
        children = _object_spans(schema, *outer["children"])
        if set(children) != FIELDS | PRESERVED:
            raise ValueError
        for name, span in children.items():
            props = m._object_spans(schema, *span, frozenset({"type", "read_only", "readonly", "read-only"}))
            kind = m._scalar(schema, props["type"])
            wanted = ("integer" if name in _INTEGERS | {"credential-expiry-after"}
                else "datetime" if name in _DATES | {"last-credential-change-date"}
                else "string" if name in _RELATIONS | {"name"} else "option")
            if (kind != wanted
                    or any(m._scalar(schema, value) is not False for key, value in props.items() if key != "type")):
                raise ValueError
        schema_digest = _token_digest(schema, row)
        row = _one(defaults, _envelope(defaults, path="secret", name="policy",
            serial_digest=binding.serial_digest, action="default"))
        fields = _object_spans(defaults, *row)
        if set(fields) != FIELDS | PRESERVED:
            raise ValueError
        values = {key:json.loads(defaults[slice(*value)]) for key, value in fields.items()}
        _values(values)
        _preserved(values)
        if values["name"] != "" or any(values[key] != "" for key in _RELATIONS):
            raise ValueError
        defaults_digest = _token_digest(defaults, row)
        body = {**{key:values[key] for key in FIELDS}, **dict.fromkeys(DISABLED, "disable"), **_NORMALIZED,
                "name":binding.name, "$originalName":""}
        _profile(body, binding.name)
        body_json = _encode(body)
        body_digest = hashlib.sha256(body_json.encode()).hexdigest()
        expected = {**{key:body[key] for key in FIELDS}, **{key:values[key] for key in PRESERVED}}
        defaults_json = None
        if profile == CANONICAL_PROFILE:
            # Preserve native member order. Refuse unfamiliar token encodings
            # rather than changing the original source digest's meaning.
            defaults_json = json.dumps(values, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
            if hashlib.sha256(defaults_json.encode()).hexdigest() != defaults_digest:
                raise ValueError
            expected = _canonical_expected(body, values)
        elif profile != STRICT_PROFILE:
            raise ValueError
        expected_json = _encode(expected)
        expected_digest = hashlib.sha256(expected_json.encode()).hexdigest()
        request = WindowsExecutionPolicyRequest(binding, schema_digest, defaults_digest, body_json,
            body_digest, expected_json, expected_digest,
            _request_digest(binding, schema_digest, defaults_digest, body_digest, expected_digest, profile, defaults_json),
            profile, defaults_json)
        request.validate()
        return request
    except Exception:
        raise WindowsExecutionPolicyError(_ERROR) from None
    finally:
        for raw in (schema, defaults):
            if type(raw) is bytearray:
                _zeroize_mutable(raw)


def consume_windows_policy_response(raw: bytearray, *, binding: WindowsExecutionPolicyBinding,
        phase: str, http_status: int) -> str:
    """Strict ACK/absence shape only; original-wire custody is independently required."""
    try:
        binding.__post_init__()
        if phase not in ("create", "delete", "absent") or type(http_status) is not int:
            raise ValueError
        method = {"create":"POST", "delete":"DELETE", "absent":"GET"}[phase]
        status = 404 if phase == "absent" else 200
        fields = _spans(raw)
        all_fields = _object_spans(raw, 0, len(raw))
        if "schema_errors" in all_fields or http_status != status:
            raise ValueError
        expected: dict[str, object] = {"version":"v7.0.0", "build":29, "path":"secret", "name":"policy",
            "vdom":"root", "http_method":method, "http_status":status,
            "status":"error" if phase == "absent" else "success"}
        for key, value in expected.items():
            actual = m._scalar(raw, fields[key])
            if type(actual) is not type(value) or actual != value:
                raise ValueError
        serial = m._text(m._scalar(raw, fields["serial"]), maximum=128)
        if hashlib.sha256(serial.encode()).hexdigest() != binding.serial_digest:
            raise ValueError
        if m._scalar(raw, fields["mkey"]) != binding.name:
            raise ValueError
        if "action" in all_fields and m._scalar(raw, all_fields["action"]) != "":
            raise ValueError
        if phase == "absent":
            # The qualified Policy detail404 has no error/results members.
            # Target's Not Found/error2 shape is a different table contract.
            if {"error", "results"} & all_fields.keys():
                raise ValueError
        elif "error" in fields:
            value = m._scalar(raw, fields["error"])
            if value is not None and (type(value) is not int or value != 0):
                raise ValueError
        return hashlib.sha256(raw).hexdigest()
    except Exception:
        raise WindowsExecutionPolicyError(_ERROR) from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


def consume_windows_policy_state(raw: bytearray, *, request: WindowsExecutionPolicyRequest) -> str:
    """Bind every fixed field and metadata; a state digest is never ownership."""
    try:
        request.validate()
        fields = _spans(raw)
        if "schema_errors" in _object_spans(raw, 0, len(raw)):
            raise ValueError
        if m._scalar(raw, fields["mkey"]) != request.binding.name:
            raise ValueError
        row = _one(raw, _envelope(raw, path="secret", name="policy", serial_digest=request.binding.serial_digest))
        members = _object_spans(raw, *row)
        if set(members) != FIELDS | PRESERVED | _META:
            raise ValueError
        values = {key:json.loads(raw[slice(*value)]) for key, value in members.items()}
        expected_state = json.loads(request.expected_state_json)
        if any(type(values[key]) is not type(expected_state[key]) or values[key] != expected_state[key]
                for key in FIELDS | PRESERVED):
            raise ValueError
        expected: dict[str, object] = {"q_origin_key":request.binding.name, "q_ref":0, "q_static":False,
            "q_no_edit":False, "q_no_rename":False, "q_global_entry":False, "q_path":"secret",
            "q_name":"policy", "q_mkey_type":"string"}
        if any(type(values[key]) is not type(value) or values[key] != value for key, value in expected.items()):
            raise ValueError
        if type(values["q_type"]) is not int or not 0 <= values["q_type"] <= 2147483647:
            raise ValueError
        return _digest((CONTRACT, request.request_digest, values))
    except Exception:
        raise WindowsExecutionPolicyError(_ERROR) from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)
