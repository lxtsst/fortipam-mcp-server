"""Private build-29 unreferenced SAML record contract; no I/O or authority.

This reproduces native serialization for one new owner-bound record. It never
writes the native source, global authentication, proxy gateways, certificates
or SCIM. A separate transport must prove absence, fresh dependencies, original
creation ownership, zero references, single dispatch and exact cleanup.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from types import MappingProxyType
from typing import NoReturn, TypeAlias
from urllib.parse import urlsplit

from v4_planning.material_provider import C3MaterialBinding

CONTRACT = "fortipam-700-build29-unreferenced-saml-create-private-v2"
NATIVE_SOURCE_NAME = "fortipam-saml-sso-server"
NATIVE_FIELDS = (
    "name", "entity-id", "single-sign-on-url", "single-logout-url", "cert",
    "idp-entity-id", "idp-single-sign-on-url", "idp-single-logout-url", "idp-cert",
    "user-name", "group-name", "adfs-claim", "group-claim-type", "user-claim-type",
    "email-attr", "display-name-attr", "scim-client",
)
SERVER_ONLY_FIELDS = (
    "clock-tolerance", "digest-method", "limit-relaystate",
    "require-signed-resp-and-asrt", "scim-group-attr-type",
)
CONFIG_FIELDS = (*NATIVE_FIELDS, *SERVER_ONLY_FIELDS)
ENDPOINT_FIELDS = (
    "entity-id", "single-sign-on-url", "single-logout-url", "idp-entity-id",
    "idp-single-sign-on-url", "idp-single-logout-url",
)
_META: Mapping[str, type[str] | type[int] | type[bool]] = MappingProxyType({
    "q_global_entry": bool, "q_mkey_type": str, "q_name": str, "q_no_edit": bool,
    "q_no_rename": bool, "q_origin_key": str, "q_path": str, "q_ref": int,
    "q_static": bool, "q_type": int,
})
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_NAME = re.compile(r"mcp-v4-saml-[a-z0-9][a-z0-9-]{0,22}\Z")
_UNAVAILABLE = "The private unreferenced SAML create contract is unavailable."
Scalar: TypeAlias = str | int | bool


class SamlServerContractError(RuntimeError):
    """Value-free refusal; no endpoint, identifier, certificate or current state."""


def _fail() -> NoReturn:
    raise SamlServerContractError(_UNAVAILABLE)


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _require_digest(value: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _fail()


def _context(*, schema_digest: str, serial_digest: str, dependencies_digest: str,
             idp_metadata_digest: str, idp_certificate_sha256: str) -> dict[str, str]:
    result = {"schema_digest": schema_digest, "serial_digest": serial_digest,
        "dependencies_digest": dependencies_digest, "idp_metadata_digest": idp_metadata_digest,
        "idp_certificate_sha256": idp_certificate_sha256}
    for value in result.values():
        _require_digest(value)
    return result


class _Private(C3MaterialBinding):
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        _fail()

    def __delattr__(self, name: str) -> None:
        _fail()


class SamlServerCreateBinding(_Private):
    """A distinct owner-selected laboratory name and one private nonce."""

    __slots__ = ("name", "nonce", "digest")
    name: str
    nonce: str
    digest: str

    def __init__(self, name: str, nonce: str) -> None:
        if type(name) is not str or len(name) > 35 or _NAME.fullmatch(name) is None:
            _fail()
        _require_digest(nonce)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "nonce", nonce)
        object.__setattr__(self, "digest", _digest({"contract": CONTRACT, "name": name, "nonce": nonce}))


def _config(value: Mapping[str, object]) -> dict[str, Scalar]:
    if not isinstance(value, Mapping) or set(value) != set(CONFIG_FIELDS):
        _fail()
    result: dict[str, Scalar] = {}
    for key in CONFIG_FIELDS:
        item = value[key]
        if key == "clock-tolerance":
            if type(item) is not int or item < 0:
                _fail()
            assert isinstance(item, int)
        else:
            if type(item) is not str or len(item) > 8192 or re.search(r"[\x00-\x1f\x7f]", item):
                _fail()
            assert isinstance(item, str)
        result[key] = item
    for key in ("adfs-claim", "limit-relaystate", "require-signed-resp-and-asrt"):
        if result[key] not in {"enable", "disable"}:
            _fail()
    return result


def _record(value: Mapping[str, object], name: str) -> dict[str, Scalar]:
    if not isinstance(value, Mapping) or set(value) != set(CONFIG_FIELDS) | set(_META):
        _fail()
    result = _config({key: value[key] for key in CONFIG_FIELDS})
    for key, kind in _META.items():
        item = value[key]
        if type(item) is not kind or isinstance(item, str) and len(item) > 8192:
            _fail()
        assert isinstance(item, (str, int, bool))
        result[key] = item
    if (result["name"] != name or result["q_origin_key"] != name or result["q_path"] != "user"
            or result["q_name"] != "saml" or result["q_mkey_type"] != "string"
            or not isinstance(result["q_ref"], int) or result["q_ref"] < 0):
        _fail()
    return result


def _source(value: Mapping[str, object]) -> dict[str, Scalar]:
    record = _record(value, NATIVE_SOURCE_NAME)
    if not record["idp-cert"]:
        _fail()
    for key in ("entity-id", "single-sign-on-url", "single-logout-url", "idp-entity-id",
                "idp-single-sign-on-url", "idp-single-logout-url"):
        item = record[key]
        assert isinstance(item, str)
        try:
            parsed = urlsplit(item)
            if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                    or parsed.fragment or parsed.scheme not in {"http", "https"}
                    or "entity-id" not in key and parsed.scheme != "https"):
                _fail()
            _ = parsed.port
        except (TypeError, ValueError):
            _fail()
    return record


def _isolated_endpoints(name: str) -> dict[str, str]:
    """Nonresolving, distinct identities; never clone a working login route."""
    sp, idp = f"https://{name}-sp.invalid", f"https://{name}-idp.invalid"
    return {"entity-id": sp + "/metadata/", "single-sign-on-url": sp + "/login/",
        "single-logout-url": sp + "/logout/", "idp-entity-id": idp + "/metadata/",
        "idp-single-sign-on-url": idp + "/login/", "idp-single-logout-url": idp + "/logout/"}


class SamlServerCreatePlan(_Private):
    """Immutable source/default/trust fingerprints and exact new-record state."""

    __slots__ = ("binding", "_source", "_defaults", "_context", "_expected", "digest")
    binding: SamlServerCreateBinding
    _source: Mapping[str, Scalar]
    _defaults: Mapping[str, Scalar]
    _context: Mapping[str, str]
    _expected: Mapping[str, Scalar]
    digest: str

    def __init__(self, binding: SamlServerCreateBinding, source: Mapping[str, object],
                 defaults: Mapping[str, object], *, schema_digest: str, serial_digest: str,
                 dependencies_digest: str, idp_metadata_digest: str, idp_certificate_sha256: str) -> None:
        if type(binding) is not SamlServerCreateBinding:
            _fail()
        original, default = _source(source), _config(defaults)
        if default["name"] != "" or default["scim-client"] != "":
            _fail()
        context = _context(schema_digest=schema_digest, serial_digest=serial_digest,
            dependencies_digest=dependencies_digest, idp_metadata_digest=idp_metadata_digest,
            idp_certificate_sha256=idp_certificate_sha256)
        expected = {**default, **{key: original[key] for key in NATIVE_FIELDS},
                    "name": binding.name, "scim-client": "", **_isolated_endpoints(binding.name)}
        if set(expected[k] for k in ENDPOINT_FIELDS) & set(original[k] for k in ENDPOINT_FIELDS):
            _fail()
        values: dict[str, object] = {"binding": binding, "_source": MappingProxyType(original),
            "_defaults": MappingProxyType(default), "_context": MappingProxyType(context),
            "_expected": MappingProxyType(expected), "digest": _digest({"contract": CONTRACT,
                "binding_digest": binding.digest, "source": original, "defaults": default,
                "expected": expected, "context": context})}
        for key, item in values.items():
            object.__setattr__(self, key, item)


def _fresh(plan: SamlServerCreatePlan, source: Mapping[str, object], defaults: Mapping[str, object],
           *, schema_digest: str, serial_digest: str, dependencies_digest: str,
           idp_metadata_digest: str, idp_certificate_sha256: str) -> None:
    if type(plan) is not SamlServerCreatePlan:
        _fail()
    context = _context(schema_digest=schema_digest, serial_digest=serial_digest,
        dependencies_digest=dependencies_digest, idp_metadata_digest=idp_metadata_digest,
        idp_certificate_sha256=idp_certificate_sha256)
    if (context != plan._context or _source(source) != plan._source or _config(defaults) != plan._defaults):
        _fail()


def build_saml_create_body(plan: SamlServerCreatePlan, source: Mapping[str, object],
                           defaults: Mapping[str, object], *, schema_digest: str, serial_digest: str,
                           dependencies_digest: str, idp_metadata_digest: str,
                           idp_certificate_sha256: str) -> bytearray:
    """Compile exactly the native 18 fields; callers must zeroize the buffer."""
    _fresh(plan, source, defaults, schema_digest=schema_digest, serial_digest=serial_digest,
        dependencies_digest=dependencies_digest, idp_metadata_digest=idp_metadata_digest,
        idp_certificate_sha256=idp_certificate_sha256)
    body = {key: plan._expected[key] for key in NATIVE_FIELDS}
    body["$originalName"] = ""
    raw = bytearray(json.dumps(body, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode())
    if len(raw) > 32768:
        raw[:] = b"\0" * len(raw)
        _fail()
    return raw


def preview_saml_create(plan: SamlServerCreatePlan, source: Mapping[str, object], defaults: Mapping[str, object], *,
                        schema_digest: str, serial_digest: str, dependencies_digest: str,
                        idp_metadata_digest: str, idp_certificate_sha256: str) -> dict[str, object]:
    """Value-free C/P/E for the exact fixture codec, with no execution claim."""
    _fresh(plan, source, defaults, schema_digest=schema_digest, serial_digest=serial_digest,
        dependencies_digest=dependencies_digest, idp_metadata_digest=idp_metadata_digest,
        idp_certificate_sha256=idp_certificate_sha256)
    delta = [name for name in SERVER_ONLY_FIELDS if plan._source[name] != plan._expected[name]]
    return {
        "contract": CONTRACT, "action_family": "saml-server.configure",
        "candidate_scope": "unreferenced_fixture_only",
        "Current State": {
            "source_configuration_fields": len(CONFIG_FIELDS),
            "candidate_absence_verified": False,
            "runtime_isolation_verified": False,
        },
        "Proposed Changes": {
            "native_configuration_field_names": list(NATIVE_FIELDS),
            "defaulted_server_field_names": list(SERVER_ONLY_FIELDS),
            "server_default_delta_field_names": delta,
            "synthetic_endpoint_field_names": list(ENDPOINT_FIELDS),
        },
        "Expected State": {
            "required_reference_count": 0,
            "scim_link_configured": False,
            "signed_response_and_assertion_required": plan._expected["require-signed-resp-and-asrt"] == "enable",
            "relaystate_limited": plan._expected["limit-relaystate"] == "enable",
        },
        "Security Changes": {
            "signature_requirement_reduced": plan._source["require-signed-resp-and-asrt"] == "enable"
                and plan._expected["require-signed-resp-and-asrt"] == "disable",
            "relaystate_limit_reduced": plan._source["limit-relaystate"] == "enable"
                and plan._expected["limit-relaystate"] == "disable",
        },
        "configuration_write_authorized": False,
        "native_backend_qualified": False,
        "runtime_isolation_qualified": False,
        "saml_login_verified": False,
        "independent_recovery_qualified": False,
    }


def verify_created_saml_record(record: Mapping[str, object], plan: SamlServerCreatePlan,
                               source: Mapping[str, object], defaults: Mapping[str, object], *,
                               schema_digest: str, serial_digest: str, dependencies_digest: str,
                               idp_metadata_digest: str, idp_certificate_sha256: str) -> None:
    """Verify all 32 fields; this alone establishes neither ownership nor login."""
    _fresh(plan, source, defaults, schema_digest=schema_digest, serial_digest=serial_digest,
        dependencies_digest=dependencies_digest, idp_metadata_digest=idp_metadata_digest,
        idp_certificate_sha256=idp_certificate_sha256)
    actual = _record(record, plan.binding.name)
    if ({key: actual[key] for key in CONFIG_FIELDS} != plan._expected or actual["q_ref"] != 0
            or actual["q_no_edit"] is not False or actual["q_static"] is not False
            or actual["q_global_entry"] is not False):
        _fail()


__all__ = ["CONFIG_FIELDS", "CONTRACT", "ENDPOINT_FIELDS", "NATIVE_FIELDS", "NATIVE_SOURCE_NAME", "SERVER_ONLY_FIELDS",
    "SamlServerContractError", "SamlServerCreateBinding", "SamlServerCreatePlan",
    "build_saml_create_body", "preview_saml_create", "verify_created_saml_record"]
