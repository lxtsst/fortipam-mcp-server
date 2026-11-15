"""Synthetic complete relationships, opaque runtime values and drift refusal."""
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp import service_account_state_projection as c
from fortipam_mcp.target_preservation_contract import TARGET_STATE_FIELDS

SERIAL = "SYNTHETIC"
KEY = b"s" * 32
UUID = "f7f20662-4d85-4fa1-b737-2e00e5f70e93"
SENTINEL = "OPAQUE_MATERIAL_SENTINEL"


def binding():
    return c.ServiceAccountStateBinding(7, "synthetic-secret", UUID, 2, "synthetic-target",
        "synthetic-updater", hashlib.sha256(SERIAL.encode()).hexdigest(), "a" * 64)


def dependency(identifier=2):
    return {"id": identifier, "target": "synthetic-target", "updater": "synthetic-updater",
        "last-update": SENTINEL, "status": SENTINEL, "msg": SENTINEL}


def rows():
    target = dict.fromkeys(TARGET_STATE_FIELDS, "preserved")
    target.update(name="synthetic-target", template="Windows User", address="192.0.2.1",
        domain="example.test", url="", hostkey=[{"hostkey-data": SENTINEL}])
    return [{"id": 7, "name": "synthetic-secret", "uuid": UUID,
             "dependency": [dependency(), dependency(3)],
             "field": [{"name": "Password", "value": SENTINEL}]}, target,
        {"name": "synthetic-updater", "type": "win-service", "restart": "disable",
         "service-name": "SyntheticService", "file-path": "", "replace-cmd": "", "restart-cmd": "",
         "q_origin_key": "synthetic-updater"}]


def response(table, row, indent=None):
    return bytearray(json.dumps(dict(version="v7.0.0", build=29, path="secret", name=table,
        http_method="GET", status="OK" if table == "database" else "success", http_status=200,
        vdom="root", serial=SERIAL, results=[row]), indent=indent).encode())


def buffers():
    secret, target, updater = rows()
    return [response("database", secret), response("target", target),
        response("dependency-updater", updater), response("dependency-updater", updater, 2),
        response("target", target, 2), response("database", secret, 2)]


def consume(raw=None, selected=None, key=KEY):
    raw = buffers() if raw is None else raw
    try:
        return c.consume_service_account_state(binding=binding() if selected is None else selected,
            witness_key=key, **dict(zip(("secret_before", "target_before", "updater_before",
                "updater_after", "target_after", "secret_after"), raw, strict=True)))
    finally:
        assert all(not value for value in raw if isinstance(value, bytearray))


def test_complete_bracket_uses_opaque_values_without_material_decoding(monkeypatch):
    original = json.loads
    def limited_decoder(value, *args, **kwargs):
        if isinstance(value, (bytes, bytearray)):
            assert SENTINEL.encode() not in value
        return original(value, *args, **kwargs)
    monkeypatch.setattr(json, "loads", limited_decoder)
    state = consume()
    assert state.dependency_count == 2 and state.bounded_windows_service_profile is True
    assert "redacted" in repr(state) and "synthetic" not in repr(binding())
    summary = state.summary()
    assert summary["complete_target_configuration_fields"] == 36
    assert summary["complete_updater_configuration_fields"] == 7
    for field in ("runtime_status_interpreted", "complete_secret_preservation_qualified",
                  "credential_consistency_qualified", "source_provenance_qualified",
                  "permission_qualified", "recovery_qualified", "execution_authorized", "runtime_registered"):
        assert summary[field] is False
    assert SENTINEL not in json.dumps(summary) and state.relation_digest not in json.dumps(summary)
    _, _, updater = rows()
    updater["replace-cmd"] = updater["restart-cmd"] = updater["file-path"] = SENTINEL
    raw = buffers()
    for index in (2, 3): raw[index][:] = response("dependency-updater", updater)
    assert consume(raw).bounded_windows_service_profile is False


@pytest.mark.parametrize("table,field", [("dependency", name) for name in c._DEPENDENCY]
    + [("updater", name) for name in c._UPDATER | {"q_origin_key"}]
    + [("target", "hostkey"), ("target", "address"), ("target", "access")])
def test_any_selected_configuration_runtime_or_metadata_drift_refuses(table, field):
    secret, target, updater = rows()
    if table == "dependency":
        secret["dependency"][0][field] = 4 if field == "id" else "changed"
        changed = response("database", secret); index = 5
    elif table == "target":
        target[field] = "changed"
        changed = response("target", target); index = 4
    else:
        updater[field] = "changed"
        changed = response("dependency-updater", updater); index = 3
    raw = buffers(); raw[index][:] = changed
    with pytest.raises(c.ServiceAccountStateProjectionError, match=r"^The private service-account state projection is unavailable\.$"):
        consume(raw)


@pytest.mark.parametrize("fault", ["extra-dependency-field", "missing-dependency-field", "duplicate-id",
    "out-of-range-id", "bool-id", "missing-selected", "wrong-target", "wrong-updater", "unknown-secret-field",
    "unknown-updater-field", "missing-updater-field", "unknown-target-field", "duplicate-key",
    "wrong-version", "wrong-serial", "wrong-status", "truncated", "trailing-json", "limit", "size",
    "status-container", "msg-container", "dependency-object", "extra-row"])
def test_partial_unknown_ambiguous_or_incomplete_sources_fail_closed(fault):
    secret, target, updater = rows()
    dep = secret["dependency"][0]
    if fault == "extra-dependency-field": dep["unknown"] = SENTINEL
    elif fault == "missing-dependency-field": del dep["msg"]
    elif fault == "duplicate-id": secret["dependency"].append(dependency())
    elif fault == "out-of-range-id": dep["id"] = 65
    elif fault == "bool-id": dep["id"] = True
    elif fault == "missing-selected": secret["dependency"] = []
    elif fault == "wrong-target": dep["target"] = "other"
    elif fault == "wrong-updater": dep["updater"] = "other"
    elif fault == "unknown-secret-field": secret["unknown"] = SENTINEL
    elif fault == "unknown-updater-field": updater["unknown"] = SENTINEL
    elif fault == "missing-updater-field": del updater["replace-cmd"]
    elif fault == "unknown-target-field": target["unknown"] = SENTINEL
    elif fault == "status-container": dep["status"] = []
    elif fault == "msg-container": dep["msg"] = {}
    elif fault == "dependency-object": secret["dependency"] = {}
    raw = buffers()
    raw[0][:] = response("database", secret)
    raw[1][:] = response("target", target)
    raw[2][:] = response("dependency-updater", updater)
    if fault == "duplicate-key": raw[0][:] = raw[0].replace(b'"id": 2', b'"id": 2,"id": 2')
    elif fault == "wrong-version": raw[0][:] = raw[0].replace(b'v7.0.0', b'v1.9.1')
    elif fault == "wrong-serial": raw[0][:] = raw[0].replace(b'SYNTHETIC', b'OTHER')
    elif fault == "wrong-status": raw[0][:] = raw[0].replace(b'"OK"', b'"success"')
    elif fault == "truncated": del raw[0][-1]
    elif fault == "trailing-json": raw[0].extend(b'{}')
    elif fault == "limit": raw[0][:] = raw[0].replace(b'"results":', b'"limit_reached":true,"results":')
    elif fault == "size": raw[0][:] = raw[0].replace(b'"results":', b'"size":2,"results":')
    elif fault == "extra-row": raw[0][:] = raw[0].replace(b'"results": [', b'"results": [{},')
    with pytest.raises(c.ServiceAccountStateProjectionError): consume(raw)


@pytest.mark.parametrize("field,value", [("type", "other"), ("restart", "enable"),
    ("file-path", SENTINEL), ("replace-cmd", SENTINEL), ("restart-cmd", SENTINEL),
    ("service-name", ""), ("service-name", "unsafe;command"), ("service-name", "a" * 65)])
def test_unbounded_updater_is_preserved_but_never_classified_as_bounded_profile(field, value):
    _, _, updater = rows(); updater[field] = value
    raw = buffers()
    for index in (2, 3): raw[index][:] = response("dependency-updater", updater)
    assert consume(raw).bounded_windows_service_profile is False


def test_private_source_context_and_witness_key_bind_the_relation_but_grant_no_provenance():
    state = consume()
    assert consume(selected=replace(binding(), source_context_digest="b" * 64)).relation_digest != state.relation_digest
    different_key = consume(key=b"x" * 32)
    assert different_key.dependency_digest != state.dependency_digest
    assert different_key.updater_state_digest != state.updater_state_digest
    assert different_key.summary()["source_provenance_qualified"] is False


def test_unselected_dependency_drift_is_significant_but_erased_credential_render_is_not_a_witness():
    secret, _, _ = rows()
    secret["dependency"][1]["msg"] = "changed-unselected-message"
    raw = buffers(); raw[5][:] = response("database", secret)
    with pytest.raises(c.ServiceAccountStateProjectionError): consume(raw)
    secret, _, _ = rows()
    secret["field"][0]["value"] = "different-masked-render"
    raw = buffers(); raw[5][:] = response("database", secret)
    assert consume(raw).summary()["complete_secret_preservation_qualified"] is False


def test_all_64_dependency_rows_and_maximum_bound_ids_are_supported():
    selected = replace(binding(), secret_id=2_147_483_647, dependency_id=64)
    secret, _, _ = rows()
    secret["id"] = selected.secret_id
    secret["dependency"] = [dependency(identifier) for identifier in range(1, 65)]
    raw = buffers()
    for index in (0, 5): raw[index][:] = response("database", secret)
    assert consume(raw, selected).dependency_count == 64


@pytest.mark.parametrize("field", sorted(c._UPDATER_METADATA))
def test_every_native_observed_updater_metadata_field_is_bound_opaquely(field):
    _, _, updater = rows()
    updater.update({name: {"opaque": SENTINEL} for name in c._UPDATER_METADATA - {"q_origin_key"}})
    raw = buffers()
    for index in (2, 3): raw[index][:] = response("dependency-updater", updater)
    assert consume(raw).bounded_windows_service_profile is True
    raw = buffers(); raw[2][:] = response("dependency-updater", updater)
    updater[field] = "changed"
    raw[3][:] = response("dependency-updater", updater)
    with pytest.raises(c.ServiceAccountStateProjectionError): consume(raw)


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize("fault", ["schema_errors", "unknown-envelope", "duplicate-envelope", "matched-count"])
def test_all_three_detail_envelopes_refuse_error_unknown_or_ambiguous_fields(index, fault):
    raw = buffers()
    if fault == "schema_errors": raw[index][:] = raw[index].replace(b'"results":', b'"schema_errors":[],"results":')
    elif fault == "unknown-envelope": raw[index][:] = raw[index].replace(b'"results":', b'"unknown":true,"results":')
    elif fault == "duplicate-envelope": raw[index][:] = raw[index].replace(b'"build": 29', b'"build":29,"build":29')
    elif fault == "matched-count": raw[index][:] = raw[index].replace(b'"results":', b'"matched_count":2,"results":')
    with pytest.raises(c.ServiceAccountStateProjectionError): consume(raw)


@pytest.mark.parametrize("fault", ["alias", "foreign", "tamper", "key", "immutable", "oversized"])
def test_invalid_ownership_of_buffers_binding_or_key_refuses_and_clears(fault):
    raw = buffers(); selected = binding(); key = KEY
    if fault == "alias": raw[5] = raw[0]
    elif fault == "foreign": selected = {"secret_id": 7}
    elif fault == "tamper": object.__setattr__(selected, "dependency_id", True)
    elif fault == "key": key = b"short"
    elif fault == "immutable": raw[0] = bytes(raw[0])
    elif fault == "oversized": raw[0] = bytearray(c.m._MAX_BYTES + 1)
    with pytest.raises(c.ServiceAccountStateProjectionError): consume(raw, selected, key)
