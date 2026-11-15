"""Synthetic boundary tests for the private LDAP response projections."""
from __future__ import annotations

import copy
import dataclasses
import json
import pickle
from typing import Any

import pytest

from fortipam_mcp.ldap_server_contract import LdapServerCandidateError, LdapServerCreateBinding
from fortipam_mcp.ldap_server_projection import (
    LDAP_SCHEMA_TYPES, LdapServerDefaults, LdapServerDetail, LdapServerSchema,
    project_ldap_absence, project_ldap_ack, project_ldap_defaults, project_ldap_detail,
    project_ldap_info, project_ldap_schema,
)
from v4_planning.material_provider import C3MaterialBinding, MaterialAccessDenied

SERIAL = "SYNTHETIC_DEVICE"
PASSWORD = "SYNTHETIC_PASSWORD_VALUE_CANARY"
OPAQUE = "SYNTHETIC_UNCLASSIFIED_VALUE_CANARY"


def binding() -> LdapServerCreateBinding:
    return LdapServerCreateBinding("mcp-v4-ldap-test", "dc.lab.example", "OU=Test,DC=lab,DC=example",
        "synthetic-ca", "bind@lab.example", "a" * 64, "c" * 64)


def envelope(**overrides: Any) -> dict[str, Any]:
    return {"version": "v7.0.0", "build": 29, "serial": SERIAL, "http_method": "GET",
            "path": "user", "name": "ldap", "status": "success", "vdom": "root", **overrides}


def encoded(document: object) -> bytearray:
    return bytearray(json.dumps(document).encode())


def schema_document() -> dict[str, Any]:
    return envelope(action="schema", results={"children": {
        name: {"type": kind} for name, kind in LDAP_SCHEMA_TYPES.items()}})


def default_row() -> dict[str, Any]:
    # Synthetic defaults assert no actual backend literals.
    row = {name: 0 if kind == "integer" else "synthetic-default"
           for name, kind in LDAP_SCHEMA_TYPES.items()}
    row.update(name="", password=PASSWORD, **{"obtain-user-info": OPAQUE})
    return row


def projections() -> tuple[LdapServerSchema, LdapServerDefaults]:
    schema_raw = encoded(schema_document())
    schema = project_ldap_schema(schema_raw, expected_serial=SERIAL)
    assert not schema_raw
    defaults_raw = encoded(envelope(action="default", results=default_row()))
    defaults = project_ldap_defaults(defaults_raw, schema, expected_serial=SERIAL)
    assert not defaults_raw
    return schema, defaults


def detail_document() -> dict[str, Any]:
    row = default_row() | binding().desired_nonmaterial()
    row["group-object-filter"] = default_row()["group-object-filter"]
    row.update(q_ref=0, q_origin_key=binding().name)
    return envelope(results=[row], mkey=binding().name)


def test_complete_projection_is_opaque_immutable_and_nonserializable() -> None:
    schema, defaults = projections()
    raw = encoded(detail_document())
    detail = project_ldap_detail(raw, schema, defaults, binding(), expected_serial=SERIAL)
    assert not raw
    assert len(schema.types) == 35 and len(defaults.values) == len(detail.values) == 34
    assert detail.reference_count == 0
    assert detail.parameters_digest == binding().parameters_digest
    assert set(detail.opaque_token_digests) == {"password", "obtain-user-info"}
    for protected in (schema, defaults, detail):
        assert isinstance(protected, C3MaterialBinding)
        assert "redacted" in repr(protected) and binding().name not in repr(protected)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied):
                operation(protected)
        arbitrary: Any = protected
        for serializer in (json.dumps, dataclasses.asdict):
            with pytest.raises(TypeError):
                serializer(arbitrary)
        with pytest.raises(LdapServerCandidateError):
            protected.state_digest = "changed"
        with pytest.raises(LdapServerCandidateError):
            del protected.state_digest


def test_password_and_unclassified_values_are_never_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    original = json.loads

    def guarded(value: Any, *args: Any, **kwargs: Any) -> Any:
        raw = value.encode() if isinstance(value, str) else bytes(value)
        assert PASSWORD.encode() not in raw and OPAQUE.encode() not in raw
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", guarded)
    schema, defaults = projections()
    detail = project_ldap_detail(encoded(detail_document()), schema, defaults, binding(), expected_serial=SERIAL)
    assert len(detail.opaque_token_digests["password"]) == 64


@pytest.mark.parametrize("change", ["extra", "missing", "password_type", "integer_type", "duplicate"])
def test_schema_is_exact_and_failures_destroy_input(change: str) -> None:
    document = schema_document()
    children = document["results"]["children"]
    if change == "extra":
        children["new-field"] = {"type": "string"}
    elif change == "missing":
        del children["server"]
    elif change == "password_type":
        children["password"]["type"] = "string"
    elif change == "integer_type":
        children["port"]["type"] = "string"
    raw = encoded(document)
    if change == "duplicate":
        raw = raw.replace(b'"port": {"type": "integer"}',
                          b'"port": {"type": "integer"}, "port": {"type": "integer"}')
    with pytest.raises(LdapServerCandidateError, match="^The private LDAP server projection is unavailable.$"):
        project_ldap_schema(raw, expected_serial=SERIAL)
    assert not raw


@pytest.mark.parametrize("key,value", [("build", 30), ("build", True), ("serial", "OTHER"),
    ("path", "other"), ("name", "other"), ("http_method", "POST"), ("http_status", 500),
    ("vdom", "other"), ("extra-envelope-field", "unqualified")])
def test_cmdb_envelope_drift_is_rejected(key: str, value: object) -> None:
    document = schema_document()
    document[key] = value
    raw = encoded(document)
    with pytest.raises(LdapServerCandidateError):
        project_ldap_schema(raw, expected_serial=SERIAL)
    assert not raw


def test_unknown_and_duplicate_detail_fields_are_rejected_before_value_decoding(
        monkeypatch: pytest.MonkeyPatch) -> None:
    schema, defaults = projections()
    document = detail_document()
    document["results"][0]["new-sensitive-field"] = "DO_NOT_DECODE_UNKNOWN"
    original = json.loads

    def guarded(value: Any, *args: Any, **kwargs: Any) -> Any:
        raw = value.encode() if isinstance(value, str) else bytes(value)
        assert b"DO_NOT_DECODE_UNKNOWN" not in raw
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", guarded)
    unknown = encoded(document)
    duplicate = encoded(detail_document()).replace(b'"q_ref": 0', b'"q_ref": 0, "q_ref": 0')
    for raw in (unknown, duplicate):
        with pytest.raises(LdapServerCandidateError):
            project_ldap_detail(raw, schema, defaults, binding(), expected_serial=SERIAL)
        assert not raw


@pytest.mark.parametrize("count", [None, False, 0.0, -1, 1])
def test_detail_requires_explicit_integer_zero(count: object) -> None:
    schema, defaults = projections()
    document = detail_document()
    if count is None:
        del document["results"][0]["q_ref"]
    else:
        document["results"][0]["q_ref"] = count
    raw = encoded(document)
    with pytest.raises(LdapServerCandidateError):
        project_ldap_detail(raw, schema, defaults, binding(), expected_serial=SERIAL)
    assert not raw


def test_only_group_object_filter_may_normalize_to_matching_default() -> None:
    schema, defaults = projections()
    for key in defaults.values:
        document = detail_document()
        document["results"][0][key] = "unqualified-change"
        raw = encoded(document)
        with pytest.raises(LdapServerCandidateError):
            project_ldap_detail(raw, schema, defaults, binding(), expected_serial=SERIAL)
        assert not raw
    document = detail_document()
    document["results"][0]["group-object-filter"] = ""
    with pytest.raises(LdapServerCandidateError):
        project_ldap_detail(encoded(document), schema, defaults, binding(), expected_serial=SERIAL)


def test_opaque_drift_is_bound_without_decoding_password() -> None:
    schema, defaults = projections()
    first = project_ldap_detail(encoded(detail_document()), schema, defaults, binding(), expected_serial=SERIAL)
    document = detail_document()
    document["results"][0]["password"] += "_changed"
    second = project_ldap_detail(encoded(document), schema, defaults, binding(), expected_serial=SERIAL)
    assert first.state_digest != second.state_digest
    document["results"][0]["obtain-user-info"] += "_changed"
    with pytest.raises(LdapServerCandidateError):
        project_ldap_detail(encoded(document), schema, defaults, binding(), expected_serial=SERIAL)


def info_document() -> dict[str, Any]:
    # Do not invent monitor path/name/action qualification absent from retained evidence.
    return {"version": "v7.0.0", "build": 29, "serial": SERIAL, "status": "success", "results": {
        "schema": {"objectClasses": ["synthetic"], "attributeTypes": {
            f"attribute{index}": {} for index in range(3943)}},
        "general": {"configured_dn": binding().dn, "server_type": 1}, "rootdse": {}}}


def test_info_positive_shape_handles_observed_attribute_cardinality_without_tree_query() -> None:
    raw = encoded(info_document())
    assert project_ldap_info(raw, binding(), expected_serial=SERIAL) is True
    assert not raw


def test_info_projects_positive_nodes_without_interpreting_extra_result_members() -> None:
    document = info_document()
    document["results"]["synthetic_uninterpreted_member"] = {"value": PASSWORD}
    raw = encoded(document)
    assert project_ldap_info(raw, binding(), expected_serial=SERIAL) is True
    assert not raw


@pytest.mark.parametrize("change", ["empty", "error", "null_error", "missing_node", "empty_classes", "wrong_dn"])
def test_info_never_treats_absence_of_error_as_success(change: str) -> None:
    document = info_document()
    results = document["results"]
    if change == "empty":
        document["results"] = {}
    elif change == "error":
        results["error"] = {"message": PASSWORD}
    elif change == "null_error":
        results["error"] = None
    elif change == "missing_node":
        del results["rootdse"]
    elif change == "empty_classes":
        results["schema"]["objectClasses"] = []
    elif change == "wrong_dn":
        results["general"]["configured_dn"] = "wrong"
    raw = encoded(document)
    with pytest.raises(LdapServerCandidateError) as error:
        project_ldap_info(raw, binding(), expected_serial=SERIAL)
    assert PASSWORD not in str(error.value) and not raw


def test_acks_and_coupled_absence_return_only_closed_booleans() -> None:
    for method in ("POST", "DELETE"):
        raw = encoded(envelope(http_method=method, http_status=200, mkey=binding().name,
                               revision="synthetic-new", old_revision="synthetic-old", results={}))
        assert project_ldap_ack(raw, binding(), expected_serial=SERIAL, method=method) is True
        assert not raw
    raw = encoded(envelope(status="error", http_status=404))
    assert project_ldap_absence(raw, binding(), expected_serial=SERIAL, http_status=404) is True
    assert not raw
    raw = encoded(envelope(results=[{"name": "another-entry"}]))
    assert project_ldap_absence(raw, binding(), expected_serial=SERIAL, http_status=200, collection=True) is True
    assert not raw


@pytest.mark.parametrize("change", ["results", "error", "wrong_status", "wrong_mkey", "extra", "duplicate"])
def test_exact_absence_rejects_unqualified_404_shapes(change: str) -> None:
    document = envelope(status="error")
    if change == "results":
        document["results"] = []
    elif change == "error":
        document["error"] = -3
    elif change == "wrong_status":
        document["status"] = "success"
    elif change == "wrong_mkey":
        document["mkey"] = "other"
    elif change == "extra":
        document["unknown"] = PASSWORD
    raw = encoded(document)
    if change == "duplicate":
        raw = raw.replace(b'"build": 29', b'"build": 29, "build": 29')
    with pytest.raises(LdapServerCandidateError):
        project_ldap_absence(raw, binding(), expected_serial=SERIAL, http_status=404)
    assert not raw


def test_collection_presence_and_wrong_ack_are_not_accepted() -> None:
    raw = encoded(envelope(results=[{"name": binding().name}]))
    with pytest.raises(LdapServerCandidateError):
        project_ldap_absence(raw, binding(), expected_serial=SERIAL, http_status=200, collection=True)
    assert not raw
    raw = encoded(envelope(http_method="POST", mkey="other"))
    with pytest.raises(LdapServerCandidateError):
        project_ldap_ack(raw, binding(), expected_serial=SERIAL)
    assert not raw
