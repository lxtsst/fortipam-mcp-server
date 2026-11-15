"""Full Secret retention composed with the existing complete relationship."""
from dataclasses import replace
import json

import pytest

from fortipam_mcp import service_account_secret_preservation as c
from fortipam_mcp.secret_approval_build29_totp_boundary import (
    consume_secret_approval_build29_totp_response,
)
from fortipam_mcp.secret_instruction_build29_api_preservation import (
    consume_secret_instruction_build29_credential_response,
)
from test_service_account_state_projection import KEY, SENTINEL, binding, response, rows


IDENTITY = dict(id=7, name=binding().secret_name, uuid=binding().secret_uuid,
    folder=17, template="Windows User", target="synthetic-primary-target")
ENVELOPE = dict(version="v7.0.0", build=29, serial="SYNTHETIC", http_method="POST",
    http_status=200, status="OK", msg="Synthetic qualified source", **{"secret-id": 7})


def material(password=SENTINEL, totp="", key=KEY):
    def credential():
        raw = bytearray(json.dumps({**ENVELOPE, "field-id": 1, "results": password}).encode())
        result = consume_secret_instruction_build29_credential_response(raw,
            expected_secret_id=7, expected_field_id=1, http_status=200,
            content_type="application/json", expected_envelope={**ENVELOPE, "field-id": 1},
            witness_key=key)
        assert not raw
        return result
    def token():
        raw = bytearray(json.dumps({**ENVELOPE, "results": totp}).encode())
        result = consume_secret_approval_build29_totp_response(raw, http_status=200,
            content_type="application/json", expected_envelope=ENVELOPE, witness_key=key)
        assert not raw
        return result
    return c.ServiceAccountSecretMaterialBracket(credential(), credential(), token(), token())


def full_row():
    secret, _, _ = rows()
    secret.update(IDENTITY)
    secret.update(field=[{"id": 1, "name": "Password", "value": "MASKED"},
        {"id": 2, "name": "Username", "value": SENTINEL}],
        **{"totp-setting": {"status": "disable", "shared-key": None, "totp-duration": 30},
           "recording": "enable", "policy": "synthetic-policy", "checkout": "disable",
           "future-config": {"nested": [SENTINEL]}, "q_origin_key": 7})
    return secret


def buffers():
    _, target, updater = rows()
    return [response("database", full_row()), response("target", target),
        response("dependency-updater", updater), response("dependency-updater", updater, 2),
        response("target", target, 2), response("database", full_row(), 2)]


def consume(raw=None, **changes):
    raw = buffers() if raw is None else raw
    args = dict(binding=binding(), secret_identity=IDENTITY,
        secret_row_fields=frozenset(full_row()), witness_key=KEY,
        material_before=material(), material_after=material())
    args.update(changes)
    try:
        return c.consume_service_account_preserved_state(**args,
            **dict(zip(("secret_before", "target_before", "updater_before", "updater_after",
                "target_after", "secret_after"), raw, strict=True)))
    finally:
        assert all(not value for value in raw)


def preflight(raw, **changes):
    values = dict(binding=binding(), secret_identity=IDENTITY, secret_row_fields=frozenset(full_row()), witness_key=KEY)
    values.update(changes)
    return c.inspect_service_account_secret_password_field(raw, **values)


def test_source_preflight_borrows_full_row_without_decoding_material_and_reuses_consumer(monkeypatch):
    raw = buffers(); before = bytes(raw[0]); scalar = c.m._scalar
    def guarded_scalar(value, span):
        assert SENTINEL.encode() not in value[slice(*span)] and value[slice(*span)] != b'"MASKED"'
        return scalar(value, span)
    monkeypatch.setattr(c.m, "_scalar", guarded_scalar)
    assert preflight(raw[0]) == 1 and bytes(raw[0]) == before
    state = consume(raw)
    assert state.summary()["source_completeness_qualified"] is False
    assert state.summary()["source_provenance_qualified"] is False


@pytest.mark.parametrize("fault", ["identity", "metadata_only", "dependency", "duplicate_slot", "missing_password", "enabled_totp", "slot_value"])
def test_source_preflight_refuses_before_a_material_lookup(fault):
    row = full_row()
    if fault == "identity": row["uuid"] = "different-uuid"
    elif fault == "metadata_only": row = rows()[0]
    elif fault == "dependency": row["dependency"][0]["target"] = "different-target"
    elif fault == "duplicate_slot": row["field"][1]["id"] = 1
    elif fault == "missing_password": row["field"][0]["name"] = "Other"
    elif fault == "enabled_totp": row["totp-setting"]["status"] = "enable"
    else: row["field"][0]["value"] = None
    raw = response("database", row); lookups = []
    with pytest.raises(c.ServiceAccountSecretPreservationError):
        field = preflight(raw)
        lookups.append(field)
    assert not lookups and not raw


def test_source_preflight_clears_borrowed_and_temporary_buffers_on_interrupt(monkeypatch):
    raw = response("database", full_row()); temporary = []
    original = c._metadata_copy
    def tracked(*args):
        value = original(*args); temporary.append(value); return value
    monkeypatch.setattr(c, "_metadata_copy", tracked)
    monkeypatch.setattr(c, "_secret", lambda *args: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt): preflight(raw)
    assert not raw and temporary and all(not item for item in temporary)


def test_preflight_is_not_a_replacement_for_later_material_and_row_validation():
    raw = buffers()
    assert preflight(raw[0]) == 1
    row = full_row(); row["field"][0]["id"] = 3
    raw[0][:] = response("database", row); raw[5][:] = response("database", row)
    with pytest.raises(c.ServiceAccountSecretPreservationError): consume(raw)


def test_complete_join_never_decodes_values_or_exposes_private_tokens(monkeypatch):
    before, after = material(), material()
    original = json.loads
    def checked(value, *args, **kwargs):
        if isinstance(value, (bytes, bytearray)):
            assert SENTINEL.encode() not in value
        return original(value, *args, **kwargs)
    monkeypatch.setattr(json, "loads", checked)
    state = consume(material_before=before, material_after=after)
    assert state.relationship.dependency_count == 2
    assert state.relationship.bounded_windows_service_profile is True
    summary = state.summary()
    assert summary["supplied_complete_secret_row_tokens_bound"] is True
    assert summary["supplied_password_and_disabled_empty_totp_brackets_matched"] is True
    assert all(summary[name] is False for name in summary if name.endswith("_qualified"))
    assert summary["execution_authorized"] is False and summary["runtime_registered"] is False
    assert state.secret_preservation_digest not in json.dumps(summary)
    assert state.state_digest not in json.dumps(summary)
    assert SENTINEL not in repr(state) and "redacted" in repr(state)


@pytest.mark.parametrize("field", ["recording", "policy", "checkout", "future-config", "q_origin_key"])
def test_any_nonmaterial_or_unknown_field_drift_refuses(field):
    row = full_row()
    row[field] = SENTINEL
    raw = buffers(); raw[5][:] = response("database", row)
    with pytest.raises(c.ServiceAccountSecretPreservationError):
        consume(raw)


@pytest.mark.parametrize("index", [0, 1])
def test_every_credential_slot_render_remains_significant(index):
    row = full_row(); row["field"][index]["value"] = "different-render"
    raw = buffers(); raw[5][:] = response("database", row)
    with pytest.raises(c.ServiceAccountSecretPreservationError):
        consume(raw)


def test_only_direct_totp_render_is_replaced_with_an_independent_empty_witness():
    baseline = consume()
    row = full_row(); row["totp-setting"]["shared-key"] = "opaque-volatile-render"
    raw = buffers(); raw[5][:] = response("database", row)
    assert consume(raw).secret_preservation_digest == baseline.secret_preservation_digest
    row["future-config"]["shared-key"] = "different-nested-render"
    raw = buffers(); raw[5][:] = response("database", row)
    with pytest.raises(c.ServiceAccountSecretPreservationError):
        consume(raw)


@pytest.mark.parametrize("fault", ["missing-material", "different-password", "wrong-password-subject",
    "wrong-password-slot", "wrong-key", "nonempty-totp", "different-totp", "fake-empty"])
def test_masked_cmdb_tokens_cannot_replace_matching_independent_materials(fault):
    bracket = material()
    if fault == "missing-material": bracket = None
    elif fault == "different-password": bracket = material("changed")
    elif fault == "wrong-password-subject":
        bracket = replace(bracket, password_before=replace(bracket.password_before, secret_id=8))
    elif fault == "wrong-password-slot":
        bracket = replace(bracket, password_before=replace(bracket.password_before, field_id=2))
    elif fault == "wrong-key": bracket = material(key=b"x" * 32)
    elif fault == "nonempty-totp": bracket = material(totp="ABCD2345")
    elif fault == "different-totp": bracket = replace(bracket, totp_after=material(totp="ABCD2345").totp_after)
    elif fault == "fake-empty": bracket = replace(bracket,
        totp_before=replace(bracket.totp_before, material_digest="0" * 64))
    with pytest.raises(c.ServiceAccountSecretPreservationError, match=r"^The private service-account Secret preservation is unavailable\.$"):
        consume(material_after=bracket)


@pytest.mark.parametrize("fault", ["missing-field", "extra-field", "wrong-identity", "missing-username",
    "missing-password", "duplicate-slot-id", "duplicate-slot-name", "totp-enabled", "totp-container",
    "duplicate-root", "duplicate-totp", "duplicate-slot", "duplicate-identity", "null-password",
    "dependency-drift", "target-drift", "updater-drift", "alias"])
def test_partial_ambiguous_or_wrong_relationship_sources_refuse_and_erase(fault):
    row = full_row()
    if fault == "missing-field": del row["recording"]
    elif fault == "extra-field": row["new-field"] = SENTINEL
    elif fault == "wrong-identity": row["target"] = "other"
    elif fault == "missing-username": row["field"].pop()
    elif fault == "missing-password": row["field"].pop(0)
    elif fault == "duplicate-slot-id": row["field"][1]["id"] = 1
    elif fault == "duplicate-slot-name": row["field"][1]["name"] = "Password"
    elif fault == "totp-enabled": row["totp-setting"]["status"] = "enable"
    elif fault == "totp-container": row["totp-setting"]["shared-key"] = []
    elif fault == "null-password": row["field"][0]["value"] = None
    elif fault == "dependency-drift": row["dependency"][1]["msg"] = "changed"
    raw = buffers(); raw[5][:] = response("database", row)
    if fault in {"duplicate-root", "duplicate-totp", "duplicate-slot", "duplicate-identity"}:
        selected = {"duplicate-root": b'"recording": "enable"',
            "duplicate-totp": b'"shared-key": null', "duplicate-slot": b'"id": 1',
            "duplicate-identity": b'"target": "synthetic-primary-target"'}[fault]
        raw[5][:] = raw[5].replace(selected, selected + b"," + selected, 1)
    elif fault == "target-drift": raw[4][:] = raw[4].replace(b'192.0.2.1', b'192.0.2.2')
    elif fault == "updater-drift": raw[3][:] = raw[3].replace(b'SyntheticService', b'ChangedService')
    elif fault == "alias": raw[5] = raw[0]
    with pytest.raises(c.ServiceAccountSecretPreservationError):
        consume(raw)


def test_changed_stable_material_changes_the_private_digest_and_interruption_clears_every_buffer(monkeypatch):
    baseline = consume()
    changed = material("different-but-stable")
    state = consume(material_before=changed, material_after=changed)
    assert state.secret_preservation_digest != baseline.secret_preservation_digest
    raw = buffers()
    projected = []
    original = c._frame
    def interrupted(*args, **kwargs):
        if projected:
            raise KeyboardInterrupt
        result = original(*args, **kwargs)
        projected.append(result[1])
        return result
    monkeypatch.setattr(c, "_frame", interrupted)
    with pytest.raises(KeyboardInterrupt): consume(raw)
    assert projected and not projected[0]


def test_combined_state_binds_the_full_secret_and_original_relationship_context():
    baseline = consume()
    context = consume(binding=replace(binding(), source_context_digest="b" * 64))
    assert context.secret_preservation_digest == baseline.secret_preservation_digest
    assert context.state_digest != baseline.state_digest
    row = full_row(); row["future-config"]["nested"] = ["changed-stable-state"]
    raw = buffers()
    for index in (0, 5): raw[index][:] = response("database", row)
    changed = consume(raw)
    assert changed.relationship.relation_digest == baseline.relationship.relation_digest
    assert changed.state_digest != baseline.state_digest
