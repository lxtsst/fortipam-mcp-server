"""Private native-token LDAP update qualification; no I/O or execution authority.

Compilation preserves the native password JSON token without interpreting it.
It does not establish backend password preservation, ownership, or permission
to dispatch. The owner must clear each returned mutable request body after use.
"""
from __future__ import annotations

import json

from v4_planning.models import require_digest

from .ldap_server_contract import LdapServerCandidateError, LdapServerCreateBinding
from .ldap_server_projection import (
    LdapServerDefaults, LdapServerDetail, LdapServerSchema, Span,
    _ProtectedProjection, _array, _destroy, _expect, _members, _record,
    _schema, _snapshot, _top,
)

CONTRACT = "fortipam-700-build29-ldap-update-native-token-private-v1"
UPDATED_GROUP_FILTER = "(objectClass=group)"
_UNAVAILABLE = "The private LDAP update contract is unavailable."


class LdapServerUpdateExpectation(_ProtectedProjection):
    """Protected state fingerprints only; never an authorization or credential."""

    __slots__ = ("baseline_digest", "expected_digest", "schema_digest", "parameters_digest", "serial_digest")
    baseline_digest: str
    expected_digest: str
    schema_digest: str
    parameters_digest: str
    serial_digest: str

    def __init__(self, *, baseline_digest: str, expected_digest: str, schema_digest: str,
                 parameters_digest: str, serial_digest: str) -> None:
        # The caller authenticates its owner-only record and versioned contract.
        # Reconstituting fingerprints grants no object ownership or dispatch right.
        try:
            for name, value in (("baseline_digest", baseline_digest),
                                ("expected_digest", expected_digest),
                                ("schema_digest", schema_digest),
                                ("parameters_digest", parameters_digest),
                                ("serial_digest", serial_digest)):
                if type(value) is not str:
                    raise ValueError
                require_digest(value, name)
                object.__setattr__(self, name, value)
            if baseline_digest == expected_digest:
                raise ValueError
        except Exception:
            raise LdapServerCandidateError(_UNAVAILABLE) from None


def _detail(content: bytearray, schema: LdapServerSchema, defaults: LdapServerDefaults,
            binding: LdapServerCreateBinding, expected_serial: str,
            group_filter: str) -> tuple[LdapServerDetail, Span]:
    _schema(schema, expected_serial)
    if (type(binding) is not LdapServerCreateBinding or type(defaults) is not LdapServerDefaults
            or defaults.schema_digest != schema.state_digest
            or defaults.serial_digest != schema.serial_digest):
        raise ValueError
    top = _top(content, expected_serial=expected_serial)
    if "mkey" in top:
        _expect(content, top, "mkey", binding.name)
    row = _record(content, top)
    values, opaque, metadata = _snapshot(content, row)
    desired = binding.desired_nonmaterial()
    if (len(desired) != 17 or desired["group-object-filter"] != ""
            or desired["group-filter"] != "" or desired["group-member-check"] != "user-attr"
            or type(metadata.get("q_ref")) is not int or metadata["q_ref"] != 0
            or "q_origin_key" in metadata and metadata["q_origin_key"] != binding.name
            or set(values) != set(defaults.values)):
        raise ValueError
    desired["group-filter"] = group_filter
    for key, current in values.items():
        expected = (defaults.values[key] if key not in desired or key == "group-object-filter"
                    else desired[key])
        if type(current) is not type(expected) or current != expected:
            raise ValueError
    if opaque["obtain-user-info"] != defaults.opaque_token_digests["obtain-user-info"]:
        raise ValueError
    return LdapServerDetail(values, opaque, metadata, schema, binding), row["password"]


def _require_expectation(expectation: LdapServerUpdateExpectation, schema: LdapServerSchema,
                         binding: LdapServerCreateBinding) -> None:
    if (type(expectation) is not LdapServerUpdateExpectation
            or expectation.schema_digest != schema.state_digest
            or expectation.serial_digest != schema.serial_digest
            or expectation.parameters_digest != binding.parameters_digest):
        raise ValueError


def _native_body(content: bytearray, password_span: Span, binding: LdapServerCreateBinding,
                 group_filter: str) -> bytearray:
    values = binding.desired_nonmaterial()
    values["group-filter"] = group_filter
    body = bytearray()
    try:
        body.extend(json.dumps(values, sort_keys=True, separators=(",", ":")).encode())
        del body[-1:]
        body.extend(b',"password":')
        with memoryview(content)[slice(*password_span)] as token:
            body.extend(token)
        body.extend(b"}")
        return body
    except Exception:
        _destroy(body)
        raise


def prepare_ldap_server_update(content: bytearray, schema: LdapServerSchema,
                               defaults: LdapServerDefaults, binding: LdapServerCreateBinding,
                               *, expected_serial: str) -> tuple[bytearray, LdapServerUpdateExpectation]:
    """Consume exact created state; compile one fixed native 18-field update."""
    try:
        baseline, password_span = _detail(content, schema, defaults, binding, expected_serial, "")
        updated = dict(baseline.values)
        updated["group-filter"] = UPDATED_GROUP_FILTER
        expected = LdapServerDetail(updated, baseline.opaque_token_digests,
            baseline.metadata, schema, binding)
        expectation = LdapServerUpdateExpectation(baseline_digest=baseline.state_digest,
            expected_digest=expected.state_digest, schema_digest=schema.state_digest,
            parameters_digest=binding.parameters_digest, serial_digest=schema.serial_digest)
        return _native_body(content, password_span, binding, UPDATED_GROUP_FILTER), expectation
    except Exception:
        raise LdapServerCandidateError(_UNAVAILABLE) from None
    finally:
        _destroy(content)


def compile_ldap_server_restore(content: bytearray, schema: LdapServerSchema,
                                defaults: LdapServerDefaults, binding: LdapServerCreateBinding,
                                expectation: LdapServerUpdateExpectation,
                                *, expected_serial: str) -> bytearray:
    """Consume exact updated state before compiling the original native fields."""
    try:
        _require_expectation(expectation, schema, binding)
        current, password_span = _detail(content, schema, defaults, binding,
                                         expected_serial, UPDATED_GROUP_FILTER)
        if current.state_digest != expectation.expected_digest:
            raise ValueError
        return _native_body(content, password_span, binding, "")
    except Exception:
        raise LdapServerCandidateError(_UNAVAILABLE) from None
    finally:
        _destroy(content)


def project_ldap_server_update_detail(content: bytearray, schema: LdapServerSchema,
                                      defaults: LdapServerDefaults, binding: LdapServerCreateBinding,
                                      expectation: LdapServerUpdateExpectation,
                                      *, expected_serial: str, restored: bool = False) -> bool:
    """Consume readback; accept only the complete expected or original state."""
    try:
        if type(restored) is not bool:
            raise ValueError
        _require_expectation(expectation, schema, binding)
        current, _ = _detail(content, schema, defaults, binding, expected_serial,
                             "" if restored else UPDATED_GROUP_FILTER)
        expected = expectation.baseline_digest if restored else expectation.expected_digest
        if current.state_digest != expected:
            raise ValueError
        return True
    except Exception:
        raise LdapServerCandidateError(_UNAVAILABLE) from None
    finally:
        _destroy(content)


def project_ldap_server_update_ack(content: bytearray, binding: LdapServerCreateBinding,
                                   *, expected_serial: str, http_status: int) -> bool:
    """Consume only a fixed successful PUT ACK; it never proves a postcondition."""
    try:
        if type(binding) is not LdapServerCreateBinding or type(http_status) is not int or http_status != 200:
            raise ValueError
        top = _top(content, expected_serial=expected_serial, method="PUT")
        if "mkey" in top:
            _expect(content, top, "mkey", binding.name)
        if "results" in top:
            span = top["results"]
            if content[span[0]] == 123:
                if _members(content, span):
                    raise ValueError
            elif content[span[0]] != 91 or _array(content, span):
                raise ValueError
        return True
    except Exception:
        raise LdapServerCandidateError(_UNAVAILABLE) from None
    finally:
        _destroy(content)


def compile_ldap_server_existing_info_body(binding: LdapServerCreateBinding) -> bytearray:
    """Compile the native existing-mkey info request, without a password field.

    This source-backed request shape alone does not prove backend credential use.
    """
    try:
        if type(binding) is not LdapServerCreateBinding:
            raise ValueError
        binding.__post_init__()
        ldap = {"server": binding.server, "port": 636, "cn_id": "sAMAccountName", "dn": binding.dn,
                "username": binding.username, "type": 2, "ca": binding.ca_name,
                "secure": 2, "server-identity-check": 1}
        return bytearray(json.dumps({"info_only": 1, "mkey": binding.name, "ldap": ldap},
            sort_keys=True, separators=(",", ":")).encode())
    except Exception:
        raise LdapServerCandidateError(_UNAVAILABLE) from None
