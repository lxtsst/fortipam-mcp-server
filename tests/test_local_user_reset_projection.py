"""Synthetic User projection tests; never contain real credentials."""
from __future__ import annotations

import json
from typing import Any

import pytest

from fortipam_mcp.local_user_reset_http_transport import LocalUserResetHttpTransportError
from fortipam_mcp.local_user_reset_projection import project_local_user_reset_detail

NAME = "mcp-v4-user-reset-synthetic"


def _case() -> tuple[dict[str, Any], dict[str, Any]]:
    fields = {name: {"type": "option"} for name in ("status", "remote-auth", "wildcard", "guest-auth")}
    fields.update({name: {"type": "string"} for name in ("name", "accprofile", "sponsor-group", "schedule", "comments")})
    fields.update(id={"type": "integer"}, password={"type": "password-2"},
        vdom={"children": {"name": {"type": "string"}}},
        webauthn={"children": {"status": {"type": "option"}, "create-time": {"type": "datetime"},
                             "synthetic-material": {"type": "password-2"}}})
    schema = {"build": 29, "http_method": "GET", "http_status": 200, "name": "admin",
        "path": "system", "status": "success", "version": "v7.0.0", "action": "schema",
        "results": {"children": fields}}
    record = {"id": 7, "name": NAME, "status": "disable", "remote-auth": "disable",
        "wildcard": "disable", "guest-auth": "enable", "accprofile": "Guest",
        "sponsor-group": "", "schedule": "", "comments": "synthetic-note",
        "password": "synthetic-password", "history0": "synthetic-history",
        "history19": "synthetic-last-history", "shared-key": "synthetic-shared-key",
        "vdom": [{"name": "synthetic-scope", "q_origin_key": "synthetic-scope"}],
        "force-saml-login": "disable", "gui-custom-conf": "disable",
        "gui-default-dashboard-template": "", "gui-ignore-invalid-signature-version": "",
        "gui-ignore-release-overview-version": "", "gui-dashboard": [],
        "gui-global-menu-favorites": [], "gui-vdom-menu-favorites": [], "gui-vdom-menu-favorites-secret": [],
        "webauthn": {"status": "disable", "create-time": "", "synthetic-material": "synthetic-nested"},
        "q_ref": 0, "q_origin_key": NAME, "q_static": False, "q_global_entry": False,
        "q_mkey_type": "string", "q_name": "admin", "q_no_edit": False,
        "q_no_rename": False, "q_path": "system", "q_type": 1}
    record["webauthn"].update({"user-handle": "", "credential-id": "", "public-key": "",
                              "transports": "", "algorithm": 0})
    return schema, record


def _body(record: Any, **overrides: Any) -> bytearray:
    values = {"build": 29, "http_method": "GET", "http_status": 200, "name": "admin",
        "path": "system", "status": "success", "version": "v7.0.0", "vdom": "synthetic-scope", "results": record}
    values.update(overrides)
    return bytearray(json.dumps(values, separators=(",", ":")).encode())


def _project(schema: Any, record: Any, **overrides: Any) -> Any:
    content = _body(record, **overrides)
    try:
        return project_local_user_reset_detail(content, schema, expected_username=NAME)
    finally:
        assert not any(content)


@pytest.mark.parametrize("array", [False, True])
def test_full_projection_is_private_and_material_removed_before_whole_decode(monkeypatch: Any, array: bool) -> None:
    schema, record = _case()
    original = json.loads

    def checked(value: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(value, (bytes, bytearray)) and value.startswith(b"{"):
            assert b"synthetic-password" not in value
            assert b"synthetic-history" not in value
            assert b"synthetic-last-history" not in value
            assert b"synthetic-shared-key" not in value
            assert b"synthetic-nested" not in value
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", checked)
    result = _project(schema, [record] if array else record)
    assert result.username == NAME and result.reported_reference_count == 0
    assert result.is_local and result.guest_auth == "enable"
    assert NAME not in repr(result) and "redacted" in repr(result)


def test_material_and_key_order_changes_do_not_change_nonmaterial_digest() -> None:
    schema, record = _case()
    before = _project(schema, record)
    record.update(password="different-synthetic", history0="", history1="synthetic-added-history",
                  history19="changed-synthetic-history", **{"shared-key": "changed-synthetic-shared-key"})
    record["webauthn"]["synthetic-material"] = ""
    after = _project(schema, dict(reversed(list(record.items()))))
    assert before.nonmaterial_state_digest == after.nonmaterial_state_digest


@pytest.mark.parametrize("field,value", [("comments", "changed"), ("q_ref", 1),
    ("schedule", "changed"), ("q_static", True), ("q_no_edit", True), ("q_type", 2),
    ("q_path", "changed"), ("force-saml-login", "enable"), ("gui-custom-conf", "enable"),
    ("gui-default-dashboard-template", "changed"), ("gui-ignore-release-overview-version", "changed"),
    ("gui-ignore-invalid-signature-version", "changed")])
def test_every_nonmaterial_field_is_in_digest(field: str, value: Any) -> None:
    schema, record = _case()
    before = _project(schema, record)
    record[field] = value
    assert before.nonmaterial_state_digest != _project(schema, record).nonmaterial_state_digest


def test_nested_nonmaterial_change_is_in_digest() -> None:
    schema, record = _case()
    before = _project(schema, record)
    record["webauthn"]["create-time"] = "changed"
    assert before.nonmaterial_state_digest != _project(schema, record).nonmaterial_state_digest


def test_schema_declared_nonmaterial_history_name_is_preserved() -> None:
    schema, record = _case()
    schema["results"]["children"]["history_policy"] = {"type": "string"}
    record["history_policy"] = "first"
    before = _project(schema, record)
    record["history_policy"] = "changed"
    assert before.nonmaterial_state_digest != _project(schema, record).nonmaterial_state_digest


@pytest.mark.parametrize("field", ["revision", "serial", "vdom"])
@pytest.mark.parametrize("bad_token", [b"not_json", b"false", b"[]", b'"bad\\x"'])
def test_ignored_envelope_values_are_still_validated(field: str, bad_token: bytes) -> None:
    schema, record = _case()
    content = _body(record, **{field: "synthetic-envelope"}).replace(b'"synthetic-envelope"', bad_token)
    with pytest.raises(LocalUserResetHttpTransportError):
        project_local_user_reset_detail(content, schema, expected_username=NAME)
    assert not any(content)


def test_unknown_history_field_is_not_silently_excluded() -> None:
    schema, record = _case()
    record["history20"] = "synthetic-unqualified-history"
    with pytest.raises(LocalUserResetHttpTransportError):
        _project(schema, record)


@pytest.mark.parametrize("change", ["missing_ref", "bool_ref", "float_ref", "negative_ref", "missing_field",
    "extra_field", "nested_missing", "nested_extra", "bad_schema", "bad_version", "wrong_user", "zero_id",
    "multiple_records", "empty_results", "material_object", "new_schema_field", "unknown_schema_type"])
def test_incomplete_or_ambiguous_projection_fails_closed(change: str) -> None:
    schema, record = _case()
    values: Any = record
    overrides = {}
    if change == "missing_ref": del record["q_ref"]
    elif change == "bool_ref": record["q_ref"] = False
    elif change == "float_ref": record["q_ref"] = 0.0
    elif change == "negative_ref": record["q_ref"] = -1
    elif change == "missing_field": del record["comments"]
    elif change == "extra_field": record["unclassified"] = "synthetic"
    elif change == "nested_missing": del record["webauthn"]["create-time"]
    elif change == "nested_extra": record["webauthn"]["unclassified"] = "synthetic"
    elif change == "bad_schema": schema["results"]["children"]["password"]["type"] = "string"
    elif change == "bad_version": overrides["build"] = 30
    elif change == "wrong_user": record["name"] = "mcp-v4-user-reset-other"
    elif change == "zero_id": record["id"] = 0
    elif change == "multiple_records": values = [record, record]
    elif change == "empty_results": values = []
    elif change == "material_object": record["password"] = {"unknown": "synthetic"}
    elif change == "new_schema_field": schema["results"]["children"]["new-field"] = {"type": "string"}
    elif change == "unknown_schema_type": schema["results"]["children"]["comments"]["type"] = "unqualified"
    with pytest.raises(LocalUserResetHttpTransportError) as failure:
        _project(schema, values, **overrides)
    assert failure.value.__cause__ is None and failure.value.__suppress_context__
    assert NAME not in str(failure.value)


@pytest.mark.parametrize("field,value", [("id", True), ("id", 7.0), ("comments", None),
    ("comments", 3), ("comments", ["synthetic"]), ("comments", {"nested": "synthetic"})])
def test_scalar_schema_type_mismatch_is_rejected(field: str, value: Any) -> None:
    schema, record = _case()
    record[field] = value
    with pytest.raises(LocalUserResetHttpTransportError):
        _project(schema, record)


@pytest.mark.parametrize("replacement", [b'"password":"bad\\x"', b'"password":not-json',
    b'"password":"a","password":"b"', b'"password":"bad\n"'])
def test_malformed_or_duplicate_material_is_not_silently_erased(replacement: bytes) -> None:
    schema, record = _case()
    content = _body(record).replace(b'"password":"synthetic-password"', replacement)
    with pytest.raises(LocalUserResetHttpTransportError):
        project_local_user_reset_detail(content, schema, expected_username=NAME)
    assert not any(content)


@pytest.mark.parametrize("mkey", [NAME, "mcp-v4-user-reset-other", None, 7])
def test_envelope_mkey_must_match_exact_bound_user(mkey: Any) -> None:
    schema, record = _case()
    if mkey == NAME:
        assert _project(schema, record, mkey=mkey).username == NAME
    else:
        with pytest.raises(LocalUserResetHttpTransportError):
            _project(schema, record, mkey=mkey)


def test_formatted_empty_gui_arrays_have_the_same_complete_state_digest() -> None:
    schema, record = _case()
    expected = _project(schema, record).nonmaterial_state_digest
    content = _body(record).replace(b"[]", b"[ \n\t ]")
    actual = project_local_user_reset_detail(content, schema, expected_username=NAME)
    assert actual.nonmaterial_state_digest == expected and not any(content)


@pytest.mark.parametrize("field", ["force-saml-login", "gui-custom-conf", "gui-dashboard",
    "gui-default-dashboard-template", "gui-ignore-release-overview-version",
    "gui-ignore-invalid-signature-version", "gui-global-menu-favorites",
    "gui-vdom-menu-favorites", "gui-vdom-menu-favorites-secret"])
def test_schema_omitted_but_observed_fields_are_required(field: str) -> None:
    schema, record = _case()
    del record[field]
    with pytest.raises(LocalUserResetHttpTransportError):
        _project(schema, record)


@pytest.mark.parametrize("field", ["gui-dashboard", "gui-global-menu-favorites",
    "gui-vdom-menu-favorites", "gui-vdom-menu-favorites-secret"])
@pytest.mark.parametrize("value", [[{}], ["synthetic"], {}, None])
def test_nonempty_or_wrong_type_gui_table_is_not_silently_dropped(field: str, value: Any) -> None:
    schema, record = _case()
    record[field] = value
    with pytest.raises(LocalUserResetHttpTransportError):
        _project(schema, record)


def test_actual_vdom_reference_remains_in_digest_without_empty_list_normalization() -> None:
    schema, record = _case()
    expected = _project(schema, record).nonmaterial_state_digest
    record["vdom"] = []
    assert _project(schema, record).nonmaterial_state_digest != expected
    record["vdom"] = [{"name": "other-scope", "q_origin_key": "other-scope"}]
    assert _project(schema, record).nonmaterial_state_digest != expected
    record["vdom"][0]["q_origin_key"] = "wrong-scope"
    with pytest.raises(LocalUserResetHttpTransportError):
        _project(schema, record)


def test_name_only_material_schema_does_not_enable_reference_value_decoding(monkeypatch: Any) -> None:
    schema, record = _case()
    schema["results"]["children"]["vdom"]["children"]["name"]["type"] = "password-2"
    record["vdom"] = [{"name": "synthetic-must-not-decode", "q_origin_key": "synthetic-must-not-decode"}]
    original = json.loads
    decoded_material = []

    def checked(value: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(value, (bytes, bytearray)) and b"synthetic-must-not-decode" in value:
            decoded_material.append(True)
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", checked)
    with pytest.raises(LocalUserResetHttpTransportError):
        _project(schema, record)
    assert not decoded_material


@pytest.mark.parametrize("field", ["user-handle", "credential-id", "public-key", "transports"])
def test_unqualified_webauthn_material_rejects_before_value_decoding(field: str, monkeypatch: Any) -> None:
    schema, record = _case()
    record["webauthn"][field] = "synthetic-must-not-decode"
    original = json.loads
    decoded_material = []

    def checked(value: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(value, (bytes, bytearray)) and b"synthetic-must-not-decode" in value:
            decoded_material.append(True)
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", checked)
    with pytest.raises(LocalUserResetHttpTransportError):
        _project(schema, record)
    assert not decoded_material


def test_webauthn_algorithm_is_preserved_and_missing_extra_field_rejects() -> None:
    schema, record = _case()
    expected = _project(schema, record).nonmaterial_state_digest
    record["webauthn"]["algorithm"] = -7
    assert _project(schema, record).nonmaterial_state_digest != expected
    del record["webauthn"]["credential-id"]
    with pytest.raises(LocalUserResetHttpTransportError):
        _project(schema, record)


@pytest.mark.parametrize("field,value", [("q_no_edit", 0), ("q_no_rename", "false"),
    ("q_type", True), ("q_type", -1), ("q_path", {}), ("q_mkey_type", 1),
    ("force-saml-login", "unqualified")])
def test_new_metadata_types_fail_closed(field: str, value: Any) -> None:
    schema, record = _case()
    record[field] = value
    with pytest.raises(LocalUserResetHttpTransportError):
        _project(schema, record)


@pytest.mark.parametrize("field", ["vdom", "webauthn"])
def test_schema_cannot_omit_current_user_scope_or_authentication_state(field: str) -> None:
    schema, record = _case()
    del schema["results"]["children"][field]
    del record[field]
    with pytest.raises(LocalUserResetHttpTransportError):
        _project(schema, record)
