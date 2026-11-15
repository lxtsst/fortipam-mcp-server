"""Offline native-token update qualification; no device or directory access."""
from __future__ import annotations

import copy
import json
import pickle
from typing import Any

import pytest

from fortipam_mcp.ldap_server_contract import LdapServerCandidateError
from fortipam_mcp.ldap_server_projection import _destroy, _members, project_ldap_detail
from fortipam_mcp.ldap_server_update_contract import (
    UPDATED_GROUP_FILTER, LdapServerUpdateExpectation,
    compile_ldap_server_existing_info_body, compile_ldap_server_restore,
    prepare_ldap_server_update, project_ldap_server_update_ack, project_ldap_server_update_detail,
)
from v4_planning.material_provider import MaterialAccessDenied

from test_ldap_server_projection import SERIAL, binding, detail_document, encoded, envelope, projections


def _updated() -> dict[str, Any]:
    document = detail_document()
    document["results"][0]["group-filter"] = UPDATED_GROUP_FILTER
    return document


def test_native_token_roundtrip_preserves_exact_bytes_and_full_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema, defaults = projections()
    token = b'"SYNTHETIC\\u005fTOKEN\\\\value"'
    document = detail_document()
    original_token = json.dumps(document["results"][0]["password"]).encode()

    def raw(document: dict[str, Any]) -> bytearray:
        return bytearray(json.dumps(document).encode().replace(original_token, token))

    baseline = project_ldap_detail(raw(document), schema, defaults, binding(), expected_serial=SERIAL)
    original_loads = json.loads

    def guarded(value: Any, *args: Any, **kwargs: Any) -> Any:
        content = value.encode() if isinstance(value, str) else bytes(value)
        assert token not in content
        return original_loads(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", guarded)
    source = raw(document)
    update, expectation = prepare_ldap_server_update(source, schema, defaults, binding(), expected_serial=SERIAL)
    assert not source
    assert expectation.baseline_digest == baseline.state_digest
    assert expectation.expected_digest != expectation.baseline_digest
    expectation = LdapServerUpdateExpectation(
        baseline_digest=expectation.baseline_digest, expected_digest=expectation.expected_digest,
        schema_digest=expectation.schema_digest, parameters_digest=expectation.parameters_digest,
        serial_digest=expectation.serial_digest)
    changed = raw(_updated())
    assert project_ldap_server_update_detail(changed, schema, defaults, binding(), expectation,
        expected_serial=SERIAL)
    assert not changed
    changed = raw(_updated())
    restore = compile_ldap_server_restore(changed, schema, defaults, binding(), expectation,
        expected_serial=SERIAL)
    assert not changed
    try:
        for body, group_filter in ((update, UPDATED_GROUP_FILTER), (restore, "")):
            fields = _members(body, (0, len(body)))
            assert set(fields) == set(binding().desired_nonmaterial()) | {"password"}
            assert len(fields) == 18
            assert body[slice(*fields["password"])] == token
            for key, expected in (binding().desired_nonmaterial() | {"group-filter": group_filter}).items():
                assert json.loads(body[slice(*fields[key])]) == expected
        restored = raw(document)
        assert project_ldap_server_update_detail(restored, schema, defaults, binding(), expectation,
            expected_serial=SERIAL, restored=True)
        assert not restored
        assert token.decode() not in repr(expectation)
        for copier in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied):
                copier(expectation)
        with pytest.raises(LdapServerCandidateError):
            expectation.baseline_digest = "changed"
    finally:
        _destroy(update)
        _destroy(restore)


@pytest.mark.parametrize("field,value", [
    ("password", "synthetic-changed-token"), ("obtain-user-info", "synthetic-changed-token"),
    ("q_ref", 1), ("q_ref", False), ("q_origin_key", "another-entry"),
    ("q_no_edit", True), ("group-filter", "(cn=*)"),
    ("group-object-filter", ""), ("server", "other.lab.example"),
    ("source-port", 42), ("unknown", "synthetic-forbidden"),
])
def test_updated_drift_cannot_qualify_or_compile_restore(field: str, value: object) -> None:
    schema, defaults = projections()
    body, expectation = prepare_ldap_server_update(encoded(detail_document()), schema, defaults,
        binding(), expected_serial=SERIAL)
    _destroy(body)
    document = _updated()
    document["results"][0][field] = value
    for restore in (False, True):
        raw = encoded(document)
        with pytest.raises(LdapServerCandidateError, match="^The private LDAP update contract is unavailable.$"):
            if restore:
                compile_ldap_server_restore(raw, schema, defaults, binding(), expectation, expected_serial=SERIAL)
            else:
                project_ldap_server_update_detail(raw, schema, defaults, binding(), expectation, expected_serial=SERIAL)
        assert not raw


@pytest.mark.parametrize("failure", ["build", "serial", "wrong_mkey", "updated_baseline", "duplicate", "unknown"])
def test_unqualified_baseline_never_compiles(failure: str) -> None:
    schema, defaults = projections()
    document = detail_document()
    if failure == "build": document["build"] = 30
    elif failure == "serial": document["serial"] = "OTHER"
    elif failure == "wrong_mkey": document["mkey"] = "other-entry"
    elif failure == "updated_baseline": document["results"][0]["group-filter"] = UPDATED_GROUP_FILTER
    elif failure == "unknown": document["results"][0]["unknown"] = "synthetic-forbidden"
    raw = encoded(document)
    if failure == "duplicate":
        raw = raw.replace(b'"q_ref": 0', b'"q_ref": 0, "q_ref": 0')
    with pytest.raises(LdapServerCandidateError):
        prepare_ldap_server_update(raw, schema, defaults, binding(), expected_serial=SERIAL)
    assert not raw


@pytest.mark.parametrize("failure", [None, "status", "method", "http_status", "mkey", "results", "unknown", "revision_result"])
def test_put_ack_is_distinct_and_unknown_results_are_rejected(failure: str | None) -> None:
    document = envelope(http_method="PUT", http_status=200, mkey=binding().name,
        old_revision="synthetic-before", revision="synthetic-after", results={})
    status = 200
    if failure == "status": document["status"] = "error"
    elif failure == "method": document["http_method"] = "POST"
    elif failure == "http_status": status = 500
    elif failure == "mkey": document["mkey"] = "other-entry"
    elif failure == "results": document["results"] = {"unknown": "synthetic-value"}
    elif failure == "unknown": document["unknown"] = True
    elif failure == "revision_result": document["results"] = [{"revision": "synthetic-after"}]
    raw = encoded(document)
    if failure is None:
        assert project_ldap_server_update_ack(raw, binding(), expected_serial=SERIAL, http_status=status)
    else:
        with pytest.raises(LdapServerCandidateError):
            project_ldap_server_update_ack(raw, binding(), expected_serial=SERIAL, http_status=status)
    assert not raw


def test_existing_info_request_has_fixed_mkey_and_no_password() -> None:
    body = compile_ldap_server_existing_info_body(binding())
    try:
        assert json.loads(body) == {"info_only": 1, "mkey": binding().name, "ldap": {
            "server": binding().server, "port": 636, "cn_id": "sAMAccountName", "dn": binding().dn,
            "username": binding().username, "type": 2, "ca": binding().ca_name,
            "secure": 2, "server-identity-check": 1}}
        assert b'"password"' not in body
    finally:
        _destroy(body)


@pytest.mark.parametrize("field", ["baseline_digest", "expected_digest", "schema_digest", "parameters_digest", "serial_digest"])
def test_restored_expectation_rejects_invalid_digest(field: str) -> None:
    values = {"baseline_digest": "a" * 64, "expected_digest": "b" * 64, "schema_digest": "c" * 64,
              "parameters_digest": "d" * 64, "serial_digest": "e" * 64}
    values[field] = "invalid-private-record"
    with pytest.raises(LdapServerCandidateError):
        LdapServerUpdateExpectation(**values)
