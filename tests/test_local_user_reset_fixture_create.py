from __future__ import annotations

import json
import pickle
from typing import Any

import pytest

from fortipam_mcp.local_user_reset_fixture_create import (
    LocalUserResetFixtureCreateError, _FIELDS, prepare_local_user_reset_fixture_create,
    verify_fixture_created_detail, verify_fixture_create_response,
)
from fortipam_mcp.local_user_reset_projection import project_local_user_reset_detail
from fortipam_mcp.local_user_reset_http_transport import LocalUserResetHttpTransportError
from v4_planning.material_provider import MaterialAccessDenied

from test_local_user_reset_projection import NAME, _body, _case


def _defaults():
    schema, record = _case()
    fields = schema["results"]["children"]
    for field in _FIELDS:
        if field not in fields:
            fields[field] = {"type": "string"}
        record.setdefault(field, "")
    fields["vdom"] = {"children": {"name": {"type": "string"}}}
    record.update(id=0, name="", status="enable", accprofile="synthetic-source-role", vdom=[])
    for field in ("guest-auth", "cert-auth", "two-factor"):
        record[field] = "disable"
    record["auto-created-user"] = "no"
    record["webauthn"] = {"status": "disable", "create-time": "", "synthetic-material": "synthetic-nested"}
    record["accprofile"] = {"q_origin_key": "synthetic-source-role"}
    record["guest-lang"] = {"q_origin_key": "synthetic-source-language"}
    record["shared-key"] = "synthetic-excluded-shared-key"
    record["history19"] = "synthetic-extra-history"
    for field in tuple(record):
        if field.startswith("q_"):
            del record[field]
    # Present in the CMDB schema and whitelist but omitted by concrete unparse.
    fields["force-saml-login"] = {"type": "option"}
    record["force-saml-login"] = "disable"
    return schema, record


def _prepare(schema: Any, record: Any, **kwargs: Any):
    content = _body(record, action="default")
    try:
        return prepare_local_user_reset_fixture_create(content, schema, username=NAME,
                                                       access_profile="Guest", **kwargs)
    finally:
        assert not any(content)


@pytest.mark.parametrize("field", sorted(_FIELDS | {"webauthn", "q_ref"}))
def test_created_readback_checks_every_submitted_field_and_reference_count(field: str) -> None:
    schema, defaults = _defaults(); draft = _prepare(schema, defaults)
    row = json.loads(draft._wire); row.update(id=17, q_ref=0)
    correct = _body(row, mkey=NAME)
    observed = verify_fixture_created_detail(correct, draft)
    assert observed.user_id == 17 and not any(correct)
    row[field] = 0 if field == "id" else 1 if field == "q_ref" else "synthetic-drift"
    content = _body(row, mkey=NAME)
    with pytest.raises(LocalUserResetFixtureCreateError): verify_fixture_created_detail(content, draft)
    assert not any(content)


def test_created_projection_does_not_decode_excluded_nested_values_or_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    schema, defaults = _defaults(); draft = _prepare(schema, defaults)
    row = json.loads(draft._wire); row.update(id=17, q_ref=0, q_no_edit="synthetic-sensitive-marker")
    row["webauthn"]["unused_key"] = "synthetic-sensitive-marker"
    attempts: list[bool] = []; original = json.loads
    def decode(value: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(value, (bytes, bytearray)) and b"synthetic-sensitive-marker" in value:
            attempts.append(True)
        return original(value, *args, **kwargs)
    monkeypatch.setattr(json, "loads", decode)
    assert verify_fixture_created_detail(_body(row, mkey=NAME), draft).user_id == 17
    row["password"] = "synthetic-sensitive-marker"
    with pytest.raises(LocalUserResetFixtureCreateError): verify_fixture_created_detail(_body(row, mkey=NAME), draft)
    assert not attempts


@pytest.mark.parametrize("updates", [
    {"mkey": "different-name"}, {"mkey": None}, {"http_method": "GET"},
    {"http_status": 403}, {"status": "error"}, {"revision_changed": False},
    {"build": 30}, {"action": "clone"},
])
def test_create_ack_requires_exact_successful_dispatch_identity(updates: dict[str, Any]) -> None:
    body = _body({}, **{"http_method": "POST", "mkey": NAME, **updates})
    with pytest.raises(LocalUserResetFixtureCreateError):
        verify_fixture_create_response(body, expected_name=NAME, expected_vdom="synthetic-scope")
    assert not any(body)


def test_create_ack_allows_source_documented_no_results_and_old_revision_metadata() -> None:
    body = _body({}, http_method="POST", mkey=NAME, old_revision="synthetic-old",
                 revision="synthetic-new", revision_changed=True)
    body = body.replace(b',"results":{}', b'')
    verify_fixture_create_response(body, expected_name=NAME, expected_vdom="synthetic-scope")
    assert not any(body)


@pytest.mark.parametrize("updates", [{"unknown": "synthetic"}, {"vdom": "other-scope"},
    {"old_revision": {}}, {"revision": None}, {"serial": 3}, {"error": 0}])
def test_create_ack_does_not_accept_arbitrary_extra_metadata_or_scope(updates: dict[str, Any]) -> None:
    body = _body({}, **{"http_method": "POST", "mkey": NAME, **updates})
    with pytest.raises(LocalUserResetFixtureCreateError):
        verify_fixture_create_response(body, expected_name=NAME, expected_vdom="synthetic-scope")
    assert not any(body)


def test_create_readback_normalizes_only_bound_scope_and_preserves_actual_vdom_digest() -> None:
    schema, defaults = _defaults(); draft = _prepare(schema, defaults)
    row = json.loads(draft._wire); row.update(id=17, q_ref=0)
    before = verify_fixture_created_detail(_body(row, mkey=NAME), draft)
    row["vdom"] = [{"name": "synthetic-scope", "q_origin_key": "synthetic-scope"}]
    after = verify_fixture_created_detail(_body(row, mkey=NAME), draft)
    assert before.request_digest == after.request_digest
    assert before.readback_digest != after.readback_digest
    assert after.username == NAME and after.user_id == 17


@pytest.mark.parametrize("vdom", [[{"name": "other-scope", "q_origin_key": "other-scope"}],
    [{"name": "synthetic-scope", "q_origin_key": "other-scope"}],
    [{"name": "synthetic-scope", "q_origin_key": "synthetic-scope", "extra": "unknown"}],
    [{"name": "synthetic-scope"}], ["synthetic-scope"], {}, None,
    [{"name": "synthetic-scope", "q_origin_key": "synthetic-scope"}] * 2])
def test_create_readback_rejects_unqualified_vdom_normalization(vdom: Any) -> None:
    schema, defaults = _defaults(); draft = _prepare(schema, defaults)
    row = json.loads(draft._wire); row.update(id=17, q_ref=0, vdom=vdom)
    body = _body(row, mkey=NAME)
    with pytest.raises(LocalUserResetFixtureCreateError):
        verify_fixture_created_detail(body, draft)
    assert not any(body)


def test_source_vdom_binds_preflight_without_changing_submitted_body() -> None:
    schema, defaults = _defaults(); first = _prepare(schema, defaults)
    second = prepare_local_user_reset_fixture_create(_body(defaults, action="default", vdom="other-scope"),
        schema, username=NAME, access_profile="Guest")
    assert first._wire == second._wire
    assert first.nonmaterial_request_digest == second.nonmaterial_request_digest
    assert first.source_defaults_digest != second.source_defaults_digest
    row = json.loads(first._wire); row.update(id=17, q_ref=0)
    with pytest.raises(LocalUserResetFixtureCreateError):
        verify_fixture_created_detail(_body(row, mkey=NAME), second)


@pytest.mark.parametrize("vdom", [None, "", 1, [], "bad\nvalue"])
def test_default_response_requires_explicit_valid_scope(vdom: Any) -> None:
    schema, defaults = _defaults(); body = _body(defaults, action="default", vdom=vdom)
    with pytest.raises(LocalUserResetFixtureCreateError):
        prepare_local_user_reset_fixture_create(body, schema, username=NAME, access_profile="Guest")
    assert not any(body)


def test_new_body_uses_exact_frontend_fields_and_never_copies_default_material(monkeypatch: pytest.MonkeyPatch) -> None:
    schema, record = _defaults()
    original = json.loads

    def decode(value: Any, *args: Any, **kwargs: Any):
        if isinstance(value, (bytes, bytearray)) and value.startswith(b"{"):
            assert all(marker not in value for marker in (
                b"synthetic-password", b"synthetic-history", b"synthetic-excluded-shared-key",
                b"synthetic-extra-history", b"synthetic-nested", b"synthetic-source-role",
                b"synthetic-source-language",
            ))
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", decode)
    draft = _prepare(schema, record)
    skeleton = json.loads(draft._wire)
    assert set(skeleton) == _FIELDS | {"webauthn"}
    assert skeleton["name"] == NAME and skeleton["id"] == 0
    assert skeleton["accprofile"] == "Guest" and skeleton["status"] == "enable"
    assert skeleton["sponsor-group"] == skeleton["schedule"] == ""
    assert skeleton["webauthn"] == {"status": "disable"} and skeleton["vdom"] == []
    assert skeleton["guest-lang"] == "en"
    assert "password" not in skeleton and "force-saml-login" not in skeleton
    assert "two-factor-authentication" not in skeleton and "auto-provision-rule" not in skeleton
    material = bytearray(b'synthetic-new-only-"value\\')
    with memoryview(material) as view:
        encoded = draft._encode(view)
        try:
            result = json.loads(encoded)
            assert result.pop("password") == material.decode()
            assert result == skeleton
        finally:
            encoded[:] = b"\x00" * len(encoded)
    assert NAME not in repr(draft)
    with pytest.raises(MaterialAccessDenied):
        pickle.dumps(draft)


def test_source_digest_covers_selected_defaults_not_unsubmitted_template_state() -> None:
    schema, record = _defaults()
    first = _prepare(schema, record)
    record.update(password="synthetic-other", history0="")
    reordered = _prepare(schema, dict(reversed(list(record.items()))))
    assert first.source_defaults_digest == reordered.source_defaults_digest
    assert first.nonmaterial_request_digest == reordered.nonmaterial_request_digest
    record["force-saml-login"] = "enable"
    changed = _prepare(schema, record)
    assert changed.source_defaults_digest == first.source_defaults_digest
    assert changed.nonmaterial_request_digest == first.nonmaterial_request_digest
    record["comments"] = "changed-synthetic-comment"
    changed = _prepare(schema, record)
    assert changed.source_defaults_digest != first.source_defaults_digest
    assert changed.nonmaterial_request_digest != first.nonmaterial_request_digest


@pytest.mark.parametrize("field,value", [
    ("id", 1), ("id", False), ("id", 0.0), ("name", NAME),
    ("remote-auth", "enable"), ("wildcard", "enable"), ("guest-auth", "enable"),
    ("cert-auth", "enable"), ("two-factor", "email"), ("auto-created-user", "yes"),
    ("auto-created-user", "disable"),
    ("sponsor-group", "synthetic-group"), ("schedule", "synthetic-schedule"),
    ("remote-group", "synthetic-group"), ("remote-server", "synthetic-server"),
    ("fortitoken", "synthetic-token"), ("email-to", "synthetic@example.test"),
    ("webauthn", [{"status": "disable", "create-time": "", "synthetic-material": ""}]),
])
def test_existing_identity_or_external_auth_defaults_are_not_a_new_fixture(field: str, value: Any) -> None:
    schema, record = _defaults()
    record[field] = value
    with pytest.raises(LocalUserResetFixtureCreateError):
        _prepare(schema, record)


@pytest.mark.parametrize("case", ["missing_field", "unknown_schema_type", "missing_password_schema", "wrong_version"])
def test_incomplete_or_unqualified_source_never_builds_a_body(case: str) -> None:
    schema, record = _defaults()
    if case == "missing_field":
        del record["comments"]
    elif case == "unknown_schema_type":
        schema["results"]["children"]["comments"]["type"] = "unqualified"
    elif case == "missing_password_schema":
        del schema["results"]["children"]["password"]
    else:
        schema["build"] = 30
    with pytest.raises(LocalUserResetFixtureCreateError):
        _prepare(schema, record)


@pytest.mark.parametrize("overrides", [{"action": "schema"}, {"http_method": "POST"},
                                      {"build": 30}, {"status": "error"}])
def test_wrong_envelope_fails_closed_and_clears_input(overrides: dict[str, Any]) -> None:
    schema, record = _defaults()
    envelope = {"action": "default", **overrides}
    content = _body(record, **envelope)
    with pytest.raises(LocalUserResetFixtureCreateError):
        prepare_local_user_reset_fixture_create(content, schema, username=NAME, access_profile="Guest")
    assert not any(content)


@pytest.mark.parametrize("value", [b"bad_json", b'"bad\\x"', b"{}"])
def test_excluded_default_material_still_requires_valid_string_encoding(value: bytes) -> None:
    schema, record = _defaults()
    content = _body(record, action="default").replace(b'"synthetic-password"', value)
    with pytest.raises(LocalUserResetFixtureCreateError):
        prepare_local_user_reset_fixture_create(content, schema, username=NAME, access_profile="Guest")
    assert not any(content)


@pytest.mark.parametrize("username,profile", [("historical-user", "Guest"), (NAME, "super_admin"),
                                           (NAME, ""), (NAME, "bad\nprofile")])
def test_invalid_requested_identity_or_profile_cannot_prepare(username: str, profile: str) -> None:
    schema, record = _defaults()
    content = _body(record, action="default")
    with pytest.raises(LocalUserResetFixtureCreateError):
        prepare_local_user_reset_fixture_create(content, schema, username=username, access_profile=profile)
    assert not any(content)


def test_initial_password_encoder_rejects_non_private_or_empty_material() -> None:
    schema, record = _defaults()
    draft = _prepare(schema, record)
    for value in (memoryview(b"synthetic-readonly"), memoryview(bytearray())):
        with value:
            with pytest.raises(LocalUserResetFixtureCreateError):
                draft._encode(value)


def test_default_reference_exception_does_not_weaken_existing_user_detail_projection() -> None:
    schema, record = _case()
    del record["q_ref"]
    content = _body(record)
    with pytest.raises(LocalUserResetHttpTransportError):
        project_local_user_reset_detail(content, schema, expected_username=NAME)
    assert not any(content)
