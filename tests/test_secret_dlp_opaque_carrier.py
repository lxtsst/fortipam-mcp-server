"""Synthetic protected byte retention, native descriptors and fixed delta checks."""

from __future__ import annotations

from copy import copy, deepcopy
import json
import pickle
from typing import Any

import pytest

from v4_planning.material_provider import MaterialAccessDenied

import fortipam_mcp.secret_dlp_opaque_carrier as carrier_module
from fortipam_mcp.secret_dlp_opaque_carrier import (
    SecretDlpOpaqueBinding, SecretDlpOpaqueCarrier, SecretDlpOpaqueCarrierError, SecretDlpOpaqueWitness,
    _FIELD_TYPES, _TEMPLATE_FIELDS,
)
from fortipam_mcp.secret_dlp_association_contract import fixed_log_only_sensor_digest, fixed_log_only_sensor_profile


SERIAL = "SYNTHETIC01"
NAME = "mcp-v4-bp005-dlp-audit-synthetic"
TARGET = "synthetic-target"
TEMPLATE = "Unix Account (SSH Password)"
SENSOR = "mcp-v4-dlp-sftp-audit-synthetic"
VALUE = "OPAQUE_SYNTHETIC_RETURN"


def _binding() -> SecretDlpOpaqueBinding:
    return SecretDlpOpaqueBinding(17, 9, NAME, TARGET, SERIAL)


def _envelope(table: str, row: object, **updates: Any) -> dict[str, Any]:
    return {"version": "v7.0.0", "build": 29, "http_status": 200, "http_method": "GET",
            "path": "secret", "name": table, "serial": SERIAL, "status": "OK", "vdom": "root",
            "action": "", "results": row, **updates}


def _secret(*, host: bool = True, keyinfo: bool = True, native: bool = False) -> dict[str, Any]:
    fields = [{"id": 2, "name": "Username", "value": "synthetic-account"},
              {"id": 1, "name": "Password", "value": VALUE}]
    if host:
        fields.append({"id": 3, "name": "Host", "value": "192.0.2.1"})
    if keyinfo:
        for field in fields: field["keyinfo"] = "OPAQUE_SYNTHETIC_KEYINFO"
    if native:
        for field in fields:
            field.update({"desc": "Synthetic field descriptor", "type": _FIELD_TYPES[str(field["name"])],
                          "q_origin_key": field["id"]})
    return _envelope("database", {"id": 17, "folder": 9, "name": NAME, "template": TEMPLATE,
        "q_origin_key": 17, "target": TARGET, "description": "Synthetic fixture", "proxy": "enable",
        "recording": "enable", "ssh-service-status": "up", "sftp-service-status": "up",
        "ssh-filter": "disable", "ssh-filter-profile": "", "dlp-status": "disable", "dlp-sensor": "",
        "field": fields, "unrelated-setting": {"preserved": "synthetic-metadata"}})


def _template() -> dict[str, Any]:
    row: dict[str, Any] = {key: [] for key in _TEMPLATE_FIELDS}
    row.update({"name": TEMPLATE, "q_origin_key": TEMPLATE, "description": "Synthetic Template",
                "field": [{"name": name, "type": kind, "q_origin_key": name, "mandatory": "enable",
                           "need-edit": "disable" if name == "Host" else "enable"}
                          for name, kind in _FIELD_TYPES.items()]})
    return _envelope("template", row)


def _raw(value: object, *, pretty: bool = False) -> bytearray:
    return bytearray(json.dumps(value, ensure_ascii=True, indent=2 if pretty else None).encode("ascii"))


def _sensor() -> dict[str, Any]:
    row: dict[str, Any] = dict(fixed_log_only_sensor_profile(sensor_name=SENSOR))
    row["q_origin_key"] = SENSOR
    row["filter"][0]["q_origin_key"] = 1
    return _envelope("sensor", row, path="dlp")


def _encode(carrier: SecretDlpOpaqueCarrier, **updates: Any) -> bytearray:
    return carrier.encode_association(_sensor(), expected_sensor_name=SENSOR,
        expected_sensor_digest=fixed_log_only_sensor_digest(_sensor(), expected_sensor_name=SENSOR),
        expected_preservation_digest=str(carrier.projection["preservation_digest"]),
        expected_opaque_field_digest=carrier.opaque_field_digest, **updates)


@pytest.mark.parametrize("host,keyinfo", [(True, True), (True, False), (False, True), (False, False)])
@pytest.mark.parametrize("native", [False, True])
def test_native_sorted_opaque_carrier_consumes_inputs_and_wipes_body(host: bool, keyinfo: bool, native: bool) -> None:
    raw, template = _raw(_secret(host=host, keyinfo=keyinfo, native=native)), _raw(_template())
    witness = SecretDlpOpaqueWitness(_binding())
    with witness:
        carrier = witness.capture(raw, template)
        assert not any(raw) and not any(template)
        assert len(carrier.opaque_field_digest) == len(carrier.redacted_metadata_witness_digest) == 64
        assert [entry["name"] for entry in carrier.credential_shape] == (
            ["Host", "Password", "Username"] if host else ["Password", "Username"])
        body = _encode(carrier)
        decoded = json.loads(body)
        assert set(decoded) == {"id", "name", "folder", "template", "target", "field", "dlp-status", "dlp-sensor"}
        assert decoded["target"] == TARGET and decoded["dlp-status"] == "enable" and decoded["dlp-sensor"] == SENSOR
        assert [entry["name"] for entry in decoded["field"]] == ["Password", "Username"]
        assert decoded["field"][0]["value"] == VALUE
        assert all(("keyinfo" in entry) is keyinfo for entry in decoded["field"])
        assert all(set(entry) == {"id", "name", "value"} | ({"keyinfo"} if keyinfo else set())
                   for entry in decoded["field"])
        for private in (witness, carrier, _binding()):
            assert all(value not in repr(private) and value not in str(private)
                       for value in (NAME, TARGET, SERIAL, VALUE, "OPAQUE_SYNTHETIC_KEYINFO"))
            for operation in (copy, deepcopy, pickle.dumps):
                with pytest.raises(MaterialAccessDenied): operation(private)
        projection = carrier.projection
        projection.clear()
        assert carrier.projection and "value" not in json.dumps(carrier.projection)
        retained = carrier._fields
        carrier.close()
        assert not any(body) and not any(retained)
        with pytest.raises(SecretDlpOpaqueCarrierError): carrier.projection
        # Individual close does not consume the shared ephemeral witness.
        next_carrier = witness.capture(_raw(_secret()), _raw(_template()))
        assert next_carrier.projection
    assert not any(witness._key)
    with pytest.raises(SecretDlpOpaqueCarrierError): next_carrier.projection


def test_values_and_keyinfo_never_enter_json_decoder(monkeypatch: Any) -> None:
    raw, template = _raw(_secret()), _raw(_template())
    original = json.loads

    def checked(content: Any, *args: Any, **kwargs: Any) -> Any:
        text = content if isinstance(content, str) else bytes(content).decode("ascii")
        assert VALUE not in text and "OPAQUE_SYNTHETIC_KEYINFO" not in text
        return original(content, *args, **kwargs)

    monkeypatch.setattr(carrier_module.json, "loads", checked)
    with SecretDlpOpaqueWitness(_binding()) as witness:
        assert witness.capture(raw, template).opaque_field_digest


def test_exact_field_bytes_and_all_non_dlp_metadata_are_independently_witnessed() -> None:
    with SecretDlpOpaqueWitness(_binding()) as witness:
        baseline = witness.capture(_raw(_secret()), _raw(_template()))
        repeat = witness.capture(_raw(_secret()), _raw(_template()))
        assert repeat.opaque_field_digest == baseline.opaque_field_digest
        assert repeat.redacted_metadata_witness_digest == baseline.redacted_metadata_witness_digest
        associated = _secret(); associated["results"].update({"dlp-status": "enable", "dlp-sensor": SENSOR})
        after = witness.capture(_raw(associated), _raw(_template()))
        assert after.redacted_metadata_witness_digest == baseline.redacted_metadata_witness_digest
        assert after.opaque_field_digest == baseline.opaque_field_digest
        body = _encode(after, restore=True)
        assert json.loads(body)["dlp-status"] == "disable" and json.loads(body)["dlp-sensor"] == ""
        changed = _secret(); changed["results"]["unrelated-setting"]["preserved"] = "changed"
        other = witness.capture(_raw(changed), _raw(_template()))
        assert other.redacted_metadata_witness_digest != baseline.redacted_metadata_witness_digest
        assert other.opaque_field_digest == baseline.opaque_field_digest
        formatted = witness.capture(_raw(_secret(), pretty=True), _raw(_template()))
        assert formatted.opaque_field_digest != baseline.opaque_field_digest
        assert formatted.redacted_metadata_witness_digest == baseline.redacted_metadata_witness_digest
        changed = _secret(); changed["results"]["field"][1]["value"] = "DIFFERENT_OPAQUE_RETURN"
        altered = witness.capture(_raw(changed), _raw(_template()))
        assert altered.opaque_field_digest != baseline.opaque_field_digest
        assert altered.redacted_metadata_witness_digest == baseline.redacted_metadata_witness_digest
    with SecretDlpOpaqueWitness(_binding()) as other_witness:
        other = other_witness.capture(_raw(_secret()), _raw(_template()))
        assert other._opaque != baseline._opaque


@pytest.mark.parametrize("table", ["secret", "template"])
@pytest.mark.parametrize("field,value", [("serial", "OTHER"), ("build", 30), ("build", True),
    ("version", "v1.9.1"), ("status", "error"), ("http_status", 200.0), ("action", "schema"),
    ("matched_count", 2), ("limit_reached", True), ("vdom", "other"), ("unknown", "field")])
def test_envelope_drift_limits_and_unknown_members_are_consumed(table: str, field: str, value: object) -> None:
    secret, template = _secret(), _template()
    (secret if table == "secret" else template)[field] = value
    raw, descriptors = _raw(secret), _raw(template)
    with SecretDlpOpaqueWitness(_binding()) as witness:
        with pytest.raises(SecretDlpOpaqueCarrierError): witness.capture(raw, descriptors)
    assert not any(raw) and not any(descriptors)


@pytest.mark.parametrize("field,value", [("id", True), ("id", 18), ("folder", 10), ("name", "other"),
    ("template", "other"), ("target", "other"), ("q_origin_key", "other")])
def test_exact_routing_identity_is_mandatory(field: str, value: object) -> None:
    secret = _secret(); secret["results"][field] = value
    with SecretDlpOpaqueWitness(_binding()) as witness:
        with pytest.raises(SecretDlpOpaqueCarrierError): witness.capture(_raw(secret), _raw(_template()))


@pytest.mark.parametrize("case", ["duplicate-name", "duplicate-id", "unknown-name", "unknown-key", "wrong-id-type",
    "value-object", "value-empty", "keyinfo-object", "missing-value", "missing-password", "extra-entry"])
def test_only_native_safe_retained_field_rows_are_accepted(case: str) -> None:
    secret = _secret(); fields = secret["results"]["field"]
    if case == "duplicate-name": fields[0]["name"] = "Password"
    elif case == "duplicate-id": fields[0]["id"] = 1
    elif case == "unknown-name": fields[0]["name"] = "User"
    elif case == "unknown-key": fields[0]["unsupported"] = True
    elif case == "wrong-id-type": fields[0]["id"] = True
    elif case == "value-object": fields[0]["value"] = {"nested": "material"}
    elif case == "value-empty": fields[1]["value"] = ""
    elif case == "keyinfo-object": fields[1]["keyinfo"] = {"nested": "material"}
    elif case == "missing-value": del fields[1]["value"]
    elif case == "missing-password": fields.pop(1)
    elif case == "extra-entry": fields.append(fields[0].copy())
    raw, descriptors = _raw(secret), _raw(_template())
    with SecretDlpOpaqueWitness(_binding()) as witness:
        with pytest.raises(SecretDlpOpaqueCarrierError): witness.capture(raw, descriptors)
    assert not any(raw) and not any(descriptors)


@pytest.mark.parametrize("case", ["name", "origin", "type", "mandatory", "need-edit", "extra", "missing", "duplicate", "row-extra"])
def test_fresh_native_unix_template_exact_descriptor_contract(case: str) -> None:
    template = _template(); row = template["results"]; field = row["field"][0]
    if case == "name": field["name"] = "Other"
    elif case == "origin": field["q_origin_key"] = "Other"
    elif case == "type": field["type"] = "username"
    elif case == "mandatory": field["mandatory"] = False
    elif case == "need-edit": field["need-edit"] = True
    elif case == "extra": field["id"] = 1
    elif case == "missing": del field["mandatory"]
    elif case == "duplicate": row["field"][1] = field.copy()
    elif case == "row-extra": row["unqualified"] = True
    with SecretDlpOpaqueWitness(_binding()) as witness:
        with pytest.raises(SecretDlpOpaqueCarrierError): witness.capture(_raw(_secret()), _raw(template))


@pytest.mark.parametrize("case", ["origin", "origin-type", "desc-type", "field-type", "missing-desc",
    "missing-type", "missing-origin", "extra-field"])
def test_native_six_field_metadata_is_cross_checked_and_never_written(case: str) -> None:
    secret = _secret(native=True, keyinfo=False)
    field = secret["results"]["field"][0]
    if case == "origin": field["q_origin_key"] = 19
    elif case == "origin-type": field["q_origin_key"] = True
    elif case == "desc-type": field["desc"] = {"name": "unsafe"}
    elif case == "field-type": field["type"] = "password"
    elif case == "missing-desc": del field["desc"]
    elif case == "missing-type": del field["type"]
    elif case == "missing-origin": del field["q_origin_key"]
    elif case == "extra-field": field["unqualified"] = True
    raw, template = _raw(secret), _raw(_template())
    with SecretDlpOpaqueWitness(_binding()) as witness:
        with pytest.raises(SecretDlpOpaqueCarrierError): witness.capture(raw, template)
    assert not any(raw) and not any(template)


@pytest.mark.parametrize("case", ["duplicate-root", "duplicate-row", "duplicate-field", "duplicate-nested",
    "trailing", "multiple-results", "malformed", "deep", "oversize"])
def test_predecode_duplicates_nested_syntax_trailing_and_size_bounds(case: str, monkeypatch: Any) -> None:
    secret = _secret(); raw = _raw(secret)
    if case == "duplicate-root": raw = raw.replace(b'"build": 29', b'"build": 29,"build": 29')
    elif case == "duplicate-row": raw = raw.replace(b'"id": 17', b'"id": 17,"id": 17')
    elif case == "duplicate-field": raw = raw.replace(b'"value": "' + VALUE.encode(), b'"value":"first","value": "' + VALUE.encode())
    elif case == "duplicate-nested": raw = raw.replace(b'"preserved":', b'"preserved":"first","preserved":')
    elif case == "trailing": raw.extend(b" {}")
    elif case == "multiple-results": secret["results"] = [secret["results"], secret["results"]]; raw = _raw(secret)
    elif case == "malformed": raw = raw.replace(b'"field": [', b'"field": [false,')
    elif case == "deep":
        node: Any = "leaf"
        for _ in range(20): node = {"nested": node}
        secret["results"]["unrelated-setting"] = node; raw = _raw(secret)
    elif case == "oversize": monkeypatch.setattr(carrier_module, "MAX_RESPONSE_BYTES", 128)
    descriptors = _raw(_template())
    with SecretDlpOpaqueWitness(_binding()) as witness:
        with pytest.raises(SecretDlpOpaqueCarrierError) as error: witness.capture(raw, descriptors)
        assert str(error.value) == "The fixed Secret DLP opaque carrier is unavailable."
        assert error.value.__cause__ is None
    assert not any(raw) and not any(descriptors)


@pytest.mark.parametrize("case", ["enable", "disable", "middle", "last", "conflict", "third", "invalid-token",
    "other-key", "nested", "template", "wrong-build"])
def test_only_native_secret_row_identical_clipboard_pair_is_normalized(case: str) -> None:
    value = "disable" if case == "disable" else "enable"
    secret = _secret(native=True, keyinfo=False)
    secret["results"]["block-clipboard"] = value
    raw, template = _raw(secret), _raw(_template())
    witness = SecretDlpOpaqueWitness(_binding())
    baseline = witness.capture(bytearray(raw), bytearray(template))
    target = b'"block-clipboard": "' + value.encode() + b'"'
    duplicate = target + b", " + target
    allowed = case in {"enable", "disable", "middle", "last"}
    if case == "conflict": duplicate = target + b', "block-clipboard": "disable"'
    elif case == "third": duplicate += b", " + target
    elif case == "invalid-token": duplicate = b'"block-clipboard": true, "block-clipboard": true'
    if case == "other-key": raw = raw.replace(b'"id": 17', b'"id": 17, "id": 17')
    elif case == "nested": raw = raw.replace(b'"preserved": "synthetic-metadata"', duplicate)
    elif case == "template": template = template.replace(b'"description": "Synthetic Template"', duplicate)
    elif case == "middle": raw = raw.replace(b'"unrelated-setting":', duplicate + b', "unrelated-setting":')
    else: raw = raw.replace(target, duplicate)
    # The middle case already contains the original final member: remove that
    # occurrence to retain exactly two members in the deliberately moved pair.
    if case == "middle": raw = raw.replace(b", " + target + b"}}", b"}}")
    if case == "wrong-build": raw = raw.replace(b'"build": 29', b'"build": 30')
    if allowed:
        result = witness.capture(raw, template)
        assert result.opaque_field_digest == baseline.opaque_field_digest
        assert result.redacted_metadata_witness_digest == baseline.redacted_metadata_witness_digest
        assert result.projection == baseline.projection
    else:
        with pytest.raises(SecretDlpOpaqueCarrierError): witness.capture(raw, template)
    assert not any(raw) and not any(template)
    witness.close()


def test_compiler_has_no_generic_patch_or_unsafe_sensor_path() -> None:
    with SecretDlpOpaqueWitness(_binding()) as witness:
        carrier = witness.capture(_raw(_secret()), _raw(_template()))
        sensor = _sensor(); sensor["results"]["filter"][0]["action"] = "block"
        with pytest.raises(SecretDlpOpaqueCarrierError):
            carrier.encode_association(sensor, expected_sensor_name=SENSOR, expected_sensor_digest="a" * 64,
                expected_preservation_digest=str(carrier.projection["preservation_digest"]),
                expected_opaque_field_digest=carrier.opaque_field_digest)
        with pytest.raises(SecretDlpOpaqueCarrierError):
            carrier.encode_association(_sensor(), expected_sensor_name=SENSOR,
                expected_sensor_digest=fixed_log_only_sensor_digest(_sensor(), expected_sensor_name=SENSOR),
                expected_preservation_digest=str(carrier.projection["preservation_digest"]),
                expected_opaque_field_digest="b" * 64)
        assert not carrier._bodies


def test_closed_witness_still_consumes_supplied_buffers() -> None:
    witness = SecretDlpOpaqueWitness(_binding()); witness.close()
    raw, template = _raw(_secret()), _raw(_template())
    with pytest.raises(SecretDlpOpaqueCarrierError): witness.capture(raw, template)
    assert not any(raw) and not any(template)
