"""Synthetic denial and non-decoding checks for the private RADIUS projection."""
from __future__ import annotations

import copy
import json
import pickle
from typing import Any

import pytest

from fortipam_mcp.radius_server_projection import (
    RADIUS_SCHEMA_TYPES, RadiusServerProjectionError, RadiusServerSchema, RadiusServerState,
    project_radius_defaults, project_radius_detail, project_radius_schema,
)
from v4_planning.material_provider import MaterialAccessDenied

SERIAL = "SYNTHETIC_RADIUS_DEVICE"
CANARY = "SYNTHETIC_OPAQUE_VALUE_DO_NOT_DECODE"


def envelope(**changes: Any) -> dict[str, Any]:
    return {"version": "v7.0.0", "build": 29, "serial": SERIAL, "http_method": "GET",
            "path": "user", "name": "radius", "status": "success", "vdom": "root", **changes}


def schema_document() -> dict[str, Any]:
    return envelope(action="schema", results={"children": {
        name: {"type": kind} if kind is not None else {}
        for name, kind in RADIUS_SCHEMA_TYPES.items()
    }})


def default_row() -> dict[str, Any]:
    # Arbitrary synthetic values are not asserted as native default literals.
    row = {name: ([] if kind is None else
                  CANARY if kind == "password" else 0 if kind == "integer" else "synthetic")
           for name, kind in RADIUS_SCHEMA_TYPES.items()}
    row.update(name="", server="", **{"secondary-server": "", "tertiary-server": "",
               "auth-type": "auto", "radius-port": 0, "require-message-authenticator": "enable"})
    return row


def encoded(document: object) -> bytearray:
    return bytearray(json.dumps(document).encode())


def schema() -> RadiusServerSchema:
    return project_radius_schema(encoded(schema_document()), expected_serial=SERIAL)


def test_complete_state_stays_private_and_consumes_input() -> None:
    shape = schema()
    raw = encoded(envelope(action="default", results=default_row()))
    baseline = project_radius_defaults(raw, shape, expected_serial=SERIAL)
    assert not raw
    assert len(baseline.values) == 38 and len(baseline.opaque_token_digests) == 6
    row = default_row() | {"name": "synthetic-radius", "server": "192.0.2.10", "q_ref": 0}
    raw = encoded(envelope(mkey="synthetic-radius", results=[row]))
    detail = project_radius_detail(raw, shape, expected_serial=SERIAL)
    assert not raw and detail.state_digest != baseline.state_digest
    assert detail.metadata["q_ref"] == 0
    for state in (shape, baseline, detail):
        assert "redacted" in repr(state) and CANARY not in repr(state)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied):
                operation(state)
        with pytest.raises(TypeError):
            json.dumps(state)
        with pytest.raises(RadiusServerProjectionError):
            state.state_digest = "changed"
    with pytest.raises(TypeError):
        baseline.values["name"] = "changed"  # type: ignore[index]


def test_passwords_and_unclassified_array_values_never_decode(monkeypatch: pytest.MonkeyPatch) -> None:
    shape = schema()
    original = json.loads

    def guarded(value: Any, *args: Any, **kwargs: Any) -> Any:
        raw = value.encode() if isinstance(value, str) else bytes(value)
        assert CANARY.encode() not in raw
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", guarded)
    raw = encoded(envelope(action="default", results=default_row()))
    baseline = project_radius_defaults(raw, shape, expected_serial=SERIAL)
    assert not raw and CANARY not in str(dict(baseline.values))
    assert CANARY not in str(dict(baseline.opaque_token_digests))


@pytest.mark.parametrize("opaque_field", ["accounting-server", "class"])
def test_populated_opaque_arrays_refuse_before_member_name_decode(
    monkeypatch: pytest.MonkeyPatch, opaque_field: str,
) -> None:
    shape = schema()
    row = default_row() | {opaque_field: [{CANARY: CANARY}]}
    raw = encoded(envelope(action="default", results=row))
    original = json.loads
    decoded_canaries: list[bool] = []

    def guarded(value: Any, *args: Any, **kwargs: Any) -> Any:
        token = value.encode() if isinstance(value, str) else bytes(value)
        if CANARY.encode() in token:
            decoded_canaries.append(True)
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", guarded)
    with pytest.raises(RadiusServerProjectionError):
        project_radius_defaults(raw, shape, expected_serial=SERIAL)
    assert not raw
    assert not decoded_canaries


@pytest.mark.parametrize("change", [
    {"build": True}, {"build": 30}, {"serial": "OTHER_DEVICE"}, {"status": "error"},
    {"http_method": "POST"}, {"name": "ldap"}, {"vdom": "OTHER"}, {"http_status": 500},
])
def test_envelope_refusal_clears_input(change: dict[str, object]) -> None:
    raw = encoded(envelope(action="default", results=default_row(), **change))
    with pytest.raises(RadiusServerProjectionError, match="^The private RADIUS state projection is unavailable.$"):
        project_radius_defaults(raw, schema(), expected_serial=SERIAL)
    assert not raw


@pytest.mark.parametrize("field,value", [
    ("new-sensitive-field", CANARY), ("timeout", True), ("secret", {"sensitive": CANARY}),
    ("accounting-server", {}), ("class", CANARY), ("radius-port", 1812),
    ("require-message-authenticator", "disable"), ("secondary-server", "192.0.2.11"),
])
def test_unqualified_defaults_refuse(field: str, value: object) -> None:
    row = default_row() | {field: value}
    raw = encoded(envelope(action="default", results=row))
    with pytest.raises(RadiusServerProjectionError):
        project_radius_defaults(raw, schema(), expected_serial=SERIAL)
    assert not raw


@pytest.mark.parametrize("mutation", ["missing", "extra", "classified_array", "wrong_type"])
def test_schema_changes_refuse(mutation: str) -> None:
    document = schema_document()
    fields = document["results"]["children"]
    if mutation == "missing":
        del fields["secret"]
    elif mutation == "extra":
        fields["new-sensitive-field"] = {"type": "password"}
    elif mutation == "classified_array":
        fields["class"] = {"type": "table"}
    else:
        fields["secret"] = {"type": "string"}
    raw = encoded(document)
    with pytest.raises(RadiusServerProjectionError):
        project_radius_schema(raw, expected_serial=SERIAL)
    assert not raw


@pytest.mark.parametrize("mutation", ["duplicate", "trailing", "missing", "other_schema"])
def test_malformed_or_cross_device_state_refuses(mutation: str) -> None:
    document = envelope(action="default", results=default_row())
    raw = encoded(document)
    shape = schema()
    if mutation == "duplicate":
        raw = raw.replace(b'"secret":', b'"secret":"synthetic", "secret":', 1)
    elif mutation == "trailing":
        raw.extend(b" null")
    elif mutation == "missing":
        del document["results"]["rsso-secret"]
        raw = encoded(document)
    else:
        shape = RadiusServerSchema("a" * 64)
    with pytest.raises(RadiusServerProjectionError):
        project_radius_defaults(raw, shape, expected_serial=SERIAL)
    assert not raw


@pytest.mark.parametrize("mutation", ["multiple", "mkey", "origin", "default", "metadata_type"])
def test_detail_identity_and_shape_refuses(mutation: str) -> None:
    row = default_row() | {"name": "synthetic-radius", "q_ref": 0, "q_origin_key": "synthetic-radius"}
    document = envelope(results=[row], mkey="synthetic-radius")
    if mutation == "multiple":
        document["results"].append(row)
    elif mutation == "mkey":
        document["mkey"] = "OTHER"
    elif mutation == "origin":
        row["q_origin_key"] = "OTHER"
    elif mutation == "default":
        document["action"] = "default"
    else:
        row["q_ref"] = False
    raw = encoded(document)
    with pytest.raises(RadiusServerProjectionError):
        project_radius_detail(raw, schema(), expected_serial=SERIAL)
    assert not raw
