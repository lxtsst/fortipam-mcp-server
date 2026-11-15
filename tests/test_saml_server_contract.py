"""Native SAML create serialization, complete state and trust-drift refusals."""
from __future__ import annotations

import copy
import json
import pickle
from typing import Any, cast

import pytest

from fortipam_mcp.saml_server_contract import (
    CONFIG_FIELDS, ENDPOINT_FIELDS, NATIVE_FIELDS, NATIVE_SOURCE_NAME, SERVER_ONLY_FIELDS,
    SamlServerContractError, SamlServerCreateBinding, SamlServerCreatePlan,
    build_saml_create_body, preview_saml_create, verify_created_saml_record,
)
from v4_planning.material_provider import MaterialAccessDenied

CONTEXT = {"schema_digest": "a" * 64, "serial_digest": "b" * 64,
    "dependencies_digest": "c" * 64, "idp_metadata_digest": "d" * 64,
    "idp_certificate_sha256": "e" * 64}


def fixture() -> tuple[dict[str, object], dict[str, object], SamlServerCreatePlan]:
    defaults: dict[str, object] = {key: "" for key in CONFIG_FIELDS}
    defaults.update({"adfs-claim": "disable", "limit-relaystate": "enable",
        "require-signed-resp-and-asrt": "disable", "clock-tolerance": 15,
        "digest-method": "sha256", "scim-group-attr-type": "string"})
    source = dict(defaults)
    source.update({"name": NATIVE_SOURCE_NAME, "entity-id": "http://sp.example/saml/metadata/",
        "single-sign-on-url": "https://sp.example/saml/login/",
        "single-logout-url": "https://sp.example/saml/logout/",
        "idp-entity-id": "https://idp.example/saml-idp/lab/metadata/",
        "idp-single-sign-on-url": "https://idp.example/saml-idp/lab/login/",
        "idp-single-logout-url": "https://idp.example/saml-idp/lab/logout/",
        "idp-cert": "synthetic-existing-idp-certificate", "scim-client": "synthetic-existing-scim",
        "user-name": "synthetic-user-attribute", "group-name": "synthetic-group-attribute",
        "clock-tolerance": 30, "require-signed-resp-and-asrt": "enable",
        "q_global_entry": False, "q_mkey_type": "string", "q_name": "saml", "q_no_edit": False,
        "q_no_rename": False, "q_origin_key": NATIVE_SOURCE_NAME, "q_path": "user", "q_ref": 4,
        "q_static": False, "q_type": 0})
    binding = SamlServerCreateBinding("mcp-v4-saml-synthetic", "f" * 64)
    return source, defaults, SamlServerCreatePlan(binding, source, defaults, **CONTEXT)


def created_record(source: dict[str, object], defaults: dict[str, object],
                   plan: SamlServerCreatePlan) -> dict[str, object]:
    return {**source, **{key: defaults[key] for key in SERVER_ONLY_FIELDS},
        "name": plan.binding.name, "q_origin_key": plan.binding.name, "q_ref": 0, "scim-client": "",
        **{field: f"https://{plan.binding.name}-{kind}.invalid/{path}/" for field, kind, path in (
            ("entity-id", "sp", "metadata"), ("single-sign-on-url", "sp", "login"),
            ("single-logout-url", "sp", "logout"), ("idp-entity-id", "idp", "metadata"),
            ("idp-single-sign-on-url", "idp", "login"), ("idp-single-logout-url", "idp", "logout"))}}


def test_native_create_preserves_source_omits_metadata_and_scim_and_verifies_all_fields() -> None:
    source, defaults, plan = fixture()
    original = copy.deepcopy((source, defaults))
    raw = build_saml_create_body(plan, source, defaults, **CONTEXT)
    try:
        body = json.loads(raw)
        assert set(body) == {*NATIVE_FIELDS, "$originalName"}
        assert body["name"] == plan.binding.name and body["$originalName"] == "" and body["scim-client"] == ""
        preserved = set(NATIVE_FIELDS) - {"name", "scim-client", *ENDPOINT_FIELDS}
        assert {k: body[k] for k in preserved} == {k: source[k] for k in preserved}
        expected = created_record(source, defaults, plan)
        assert all(body[k] == expected[k] and body[k] != source[k] for k in ENDPOINT_FIELDS)
        assert not set(SERVER_ONLY_FIELDS) & set(body) and len(body) == 18
    finally:
        raw[:] = b"\0" * len(raw)
    after = created_record(source, defaults, plan)
    assert len(after) == 32
    assert after["require-signed-resp-and-asrt"] == defaults["require-signed-resp-and-asrt"]
    assert source["require-signed-resp-and-asrt"] != after["require-signed-resp-and-asrt"]
    verify_created_saml_record(after, plan, source, defaults, **CONTEXT)
    assert (source, defaults) == original


def test_value_free_preview_exposes_native_security_default_deltas_without_authority() -> None:
    source, defaults, plan = fixture()
    preview = cast(dict[str, Any], preview_saml_create(plan, source, defaults, **CONTEXT))
    assert preview['candidate_scope'] == 'unreferenced_fixture_only'
    changes = preview['Proposed Changes']
    assert changes['native_configuration_field_names'] == list(NATIVE_FIELDS)
    assert set(changes['defaulted_server_field_names']) == set(SERVER_ONLY_FIELDS)
    assert set(changes['server_default_delta_field_names']) == {'clock-tolerance', 'require-signed-resp-and-asrt'}
    assert set(changes['synthetic_endpoint_field_names']) == set(ENDPOINT_FIELDS)
    assert preview['Security Changes']['signature_requirement_reduced'] is True
    assert preview['Expected State']['signed_response_and_assertion_required'] is False
    assert preview['Expected State']['scim_link_configured'] is False
    assert preview['Current State']['candidate_absence_verified'] is False
    assert preview['Current State']['runtime_isolation_verified'] is False
    for name in ('configuration_write_authorized', 'native_backend_qualified', 'runtime_isolation_qualified',
            'saml_login_verified', 'independent_recovery_qualified'):
        assert preview[name] is False
    rendered = json.dumps(preview)
    for private in (*[source[field] for field in ENDPOINT_FIELDS], source['idp-cert'], source['scim-client'],
            plan.binding.name, plan.binding.nonce, *CONTEXT.values()):
        assert isinstance(private, str) and private not in rendered
    changes['server_default_delta_field_names'].clear()
    fresh = cast(dict[str, Any], preview_saml_create(plan, source, defaults, **CONTEXT))
    assert fresh['Proposed Changes']['server_default_delta_field_names']


@pytest.mark.parametrize('target', ['source', 'defaults', 'context'])
def test_preview_refuses_a_different_configuration_or_trust_baseline(target: str) -> None:
    source, defaults, plan = fixture(); context = dict(CONTEXT)
    if target == 'source': source['require-signed-resp-and-asrt'] = 'disable'
    elif target == 'defaults': defaults['limit-relaystate'] = 'disable'
    else: context['dependencies_digest'] = '0'*64
    with pytest.raises(SamlServerContractError): preview_saml_create(plan, source, defaults, **context)


def test_preview_reports_relaystate_reduction_and_signature_strengthening_separately() -> None:
    source, defaults, original = fixture()
    source['require-signed-resp-and-asrt'] = 'disable'
    defaults['require-signed-resp-and-asrt'] = 'enable'
    source['limit-relaystate'] = 'enable'; defaults['limit-relaystate'] = 'disable'
    plan = SamlServerCreatePlan(original.binding, source, defaults, **CONTEXT)
    preview = cast(dict[str, Any], preview_saml_create(plan, source, defaults, **CONTEXT))
    assert preview['Security Changes'] == dict(signature_requirement_reduced=False, relaystate_limit_reduced=True)
    assert preview['Expected State']['signed_response_and_assertion_required'] is True
    assert preview['Expected State']['relaystate_limited'] is False


@pytest.mark.parametrize("field", SERVER_ONLY_FIELDS)
def test_omitted_server_fields_are_still_mandatory_exact_readback(field: str) -> None:
    source, defaults, plan = fixture()
    after = created_record(source, defaults, plan)
    after[field] = 999 if field == "clock-tolerance" else (
        "disable" if defaults[field] == "enable" else "enable" if defaults[field] == "disable" else "changed")
    with pytest.raises(SamlServerContractError):
        verify_created_saml_record(after, plan, source, defaults, **CONTEXT)


@pytest.mark.parametrize("key,value", [("q_ref", 1), ("q_ref", False), ("q_no_edit", True),
    ("q_static", True), ("q_global_entry", True), ("scim-client", "unexpected-scim"),
    ("q_origin_key", "another-record"), ("idp-cert", "another-certificate"), ("clock-tolerance", False)])
def test_created_record_cannot_be_referenced_immutable_or_drifted(key: str, value: object) -> None:
    source, defaults, plan = fixture()
    after = created_record(source, defaults, plan)
    after[key] = value
    with pytest.raises(SamlServerContractError, match="^The private unreferenced SAML create contract is unavailable.$"):
        verify_created_saml_record(after, plan, source, defaults, **CONTEXT)


@pytest.mark.parametrize("key", tuple(CONTEXT))
def test_device_schema_global_proxy_or_idp_trust_drift_never_compiles(key: str) -> None:
    source, defaults, plan = fixture()
    context = dict(CONTEXT, **{key: "0" * 64})
    with pytest.raises(SamlServerContractError):
        build_saml_create_body(plan, source, defaults, **context)


@pytest.mark.parametrize("target", ["source", "defaults", "source_metadata", "unknown_field", "missing_field"])
def test_source_or_default_drift_cannot_become_a_new_baseline(target: str) -> None:
    source, defaults, plan = fixture()
    if target == "source":
        source["display-name-attr"] = "changed"
    elif target == "defaults":
        defaults["digest-method"] = "changed"
    elif target == "source_metadata":
        source["q_ref"] = 5
    elif target == "unknown_field":
        defaults["unknown"] = "value"
    else:
        del source["email-attr"]
    with pytest.raises(SamlServerContractError):
        build_saml_create_body(plan, source, defaults, **CONTEXT)


def test_binding_enforces_native_name_limit_and_never_selects_the_shared_server() -> None:
    name = "mcp-v4-saml-" + "a" * 23
    assert len(name) == 35 and SamlServerCreateBinding(name, "f" * 64).name == name
    for invalid in (name + "b", NATIVE_SOURCE_NAME, "mcp-v4-saml-../other", "mcp-v4-saml-a\n", "mcp-v4-saml-测试"):
        with pytest.raises(SamlServerContractError):
            SamlServerCreateBinding(invalid, "f" * 64)


@pytest.mark.parametrize("key,value", [("idp-cert", ""), ("single-sign-on-url", "http://sp.example/login/"),
    ("idp-single-sign-on-url", "https://user:password@idp.example/login/"),
    ("idp-entity-id", "https://idp.example/#fragment"), ("name", "unqualified-source")])
def test_unbound_trust_or_invalid_source_cannot_create_a_plan(key: str, value: object) -> None:
    source, defaults, plan = fixture()
    source[key] = value
    with pytest.raises(SamlServerContractError):
        SamlServerCreatePlan(plan.binding, source, defaults, **CONTEXT)


def test_plan_and_binding_are_opaque_immutable_and_detached_from_input_mutation() -> None:
    source, defaults, plan = fixture()
    for value in (plan.binding, plan):
        assert "synthetic" not in repr(value)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied):
                operation(value)
        with pytest.raises(SamlServerContractError):
            setattr(value, "digest", "a" * 64)
    before = plan.digest
    source["cert"] = "changed"
    defaults["clock-tolerance"] = 999
    assert plan.digest == before
    with pytest.raises(SamlServerContractError):
        build_saml_create_body(plan, source, defaults, **CONTEXT)


@pytest.mark.parametrize("field", ENDPOINT_FIELDS)
def test_source_login_route_cannot_reappear_in_created_record(field: str) -> None:
    source, defaults, plan = fixture()
    after = created_record(source, defaults, plan)
    after[field] = source[field]
    with pytest.raises(SamlServerContractError):
        verify_created_saml_record(after, plan, source, defaults, **CONTEXT)


def test_fixture_identity_must_not_already_belong_to_shared_source() -> None:
    source, defaults, plan = fixture()
    source["entity-id"] = f"https://{plan.binding.name}-sp.invalid/metadata/"
    with pytest.raises(SamlServerContractError):
        SamlServerCreatePlan(plan.binding, source, defaults, **CONTEXT)
