"""Private complete-state preservation checks with synthetic Target responses."""
from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
import pickle

import pytest

from fortipam_mcp import target_preservation_contract as c
from v4_planning.material_provider import MaterialAccessDenied

NAME = "synthetic-target"
SERIAL = "SYNTHETIC"
DIGEST = hashlib.sha256(SERIAL.encode()).hexdigest()


def row() -> dict[str, object]:
    result: dict[str, object] = dict.fromkeys(c.TARGET_STATE_FIELDS, "synthetic-preserved")
    result.update(name=NAME, template="Synthetic Template", address="192.0.2.1", domain="example.test", url="")
    result.update({"id": 1, "creation-time": 1, "ldaps-port": 636,
        "user-permission": [{"id": 1, "user-name": [{"name": "synthetic-owner"}], "permission": "owner"}],
        "group-permission": [], "hostkey": [{"hostkey-data": "MATERIAL_SENTINEL"}],
        "service-addrs": [{"service-addr": "192.0.2.2:22", "desc": "second"}],
        "web-proxy": {"auth-url": "https://example.test", "UNSELECTED_KEY_SENTINEL": "MATERIAL_SENTINEL"},
        "sql-log": {"monitor-db": [{"name": "synthetic-db"}]},
        "q_origin_key": NAME, "q_ref": 0, "permissions": {"user": "owner"}})
    return result


def response(value: dict[str, object], *, indent: int | None = None) -> bytearray:
    return bytearray(json.dumps({"version": "v7.0.0", "build": 29, "path": "secret", "name": "target",
        "http_method": "GET", "status": "success", "http_status": 200, "vdom": "root", "serial": SERIAL,
        "results": [value], "mkey": NAME}, indent=indent).encode())


def capture(value: dict[str, object]) -> c.TargetState:
    content = response(value)
    result = c.capture_target_state(content, expected_name=NAME, expected_serial_digest=DIGEST)
    assert not any(content)
    return result


def prepared() -> tuple[dict[str, object], c.TargetCoordinateChange, c.TargetState]:
    original = row()
    baseline = capture(original)
    desired = replace(baseline.coordinates, address="192.0.2.99", url="https://example.test/new")
    current = response(original)
    body, change = c.compile_target_coordinate_update(current, baseline=baseline, desired=desired)
    assert json.loads(body) == {"address": desired.address, "url": desired.url}
    assert not any(current)
    body[:] = b"\0" * len(body)
    updated = dict(original, address=desired.address, url=desired.url)
    readback = response(updated)
    verified = c.verify_target_coordinate_update(readback, change=change)
    assert not any(readback)
    return updated, change, verified


def test_complete_state_update_and_explicit_restore_preserve_nested_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    original_loads = c.json.loads
    def selected_only(value: object, *args: object, **kwargs: object) -> object:
        if isinstance(value, (bytes, bytearray)):
            assert b"MATERIAL_SENTINEL" not in value
            assert b"UNSELECTED_KEY_SENTINEL" not in value
        return original_loads(value, *args, **kwargs)  # type: ignore[arg-type]
    monkeypatch.setattr(c.json, "loads", selected_only)
    updated, change, verified = prepared()
    current = response(updated, indent=2)
    body = c.compile_target_coordinate_restore(current, change=change, updated=verified)
    assert json.loads(body) == {"address": "192.0.2.1", "url": ""}
    assert not any(current)
    body[:] = b"\0" * len(body)
    restored = response(row())
    assert c.verify_target_coordinate_restore(restored, change=change).state_digest == change.baseline.state_digest
    assert not any(restored)


@pytest.mark.parametrize("field", sorted(c.TARGET_STATE_FIELDS - set(c._COORDINATES) - {"name"}))
def test_each_preserved_field_change_denies_post_update_and_restore(field: str) -> None:
    updated, change, verified = prepared()
    updated[field] = {"unexpected": "drift"}
    for operation in (lambda value: c.verify_target_coordinate_update(value, change=change),
                      lambda value: c.compile_target_coordinate_restore(value, change=change, updated=verified)):
        content = response(updated)
        with pytest.raises(c.TargetPreservationError, match="^Protected Target preservation unavailable\\.$"):
            operation(content)
        assert not any(content)


@pytest.mark.parametrize("fault", ["coordinate", "metadata", "missing", "extra", "identity", "serial", "version", "duplicate"])
def test_pre_dispatch_drift_or_unqualified_response_is_denied_and_cleared(fault: str) -> None:
    original = row(); baseline = capture(original)
    if fault == "coordinate": original["domain"] = "other.test"
    elif fault == "metadata": original["q_ref"] = 1
    elif fault == "missing": del original["web-proxy"]
    elif fault == "extra": original["unknown-config"] = "MATERIAL_SENTINEL"
    elif fault == "identity": original["name"] = "other-target"
    content = response(original)
    if fault == "serial": content = content.replace(b'SYNTHETIC', b'OTHER')
    elif fault == "version": content = content.replace(b'v7.0.0', b'v1.9.1')
    elif fault == "duplicate": content = content.replace(b'"name": "synthetic-target"', b'"name": "synthetic-target", "name": "synthetic-target"')
    with pytest.raises(c.TargetPreservationError):
        c.compile_target_coordinate_update(content, baseline=baseline, desired=replace(baseline.coordinates, address="192.0.2.99"))
    assert not any(content)


def test_inconsistent_snapshot_coordinates_cannot_compile_update_or_restore() -> None:
    updated, change, verified = prepared()
    forged = replace(change.baseline, coordinates=replace(change.baseline.coordinates, address="192.0.2.254"))
    for operation, values in ((lambda value: c.compile_target_coordinate_update(value, baseline=forged, desired=change.desired), row()),
                              (lambda value: c.compile_target_coordinate_restore(value, change=replace(change, baseline=forged), updated=verified), updated)):
        content = response(values)
        with pytest.raises(c.TargetPreservationError): operation(content)
        assert not any(content)


def test_wrong_updated_receipt_noop_and_incomplete_restoration_are_denied() -> None:
    updated, change, verified = prepared()
    with pytest.raises(c.TargetPreservationError):
        c.compile_target_coordinate_restore(response(updated), change=change, updated=change.baseline)
    with pytest.raises(c.TargetPreservationError):
        c.compile_target_coordinate_update(response(row()), baseline=change.baseline, desired=change.baseline.coordinates)
    with pytest.raises(c.TargetPreservationError):
        c.verify_target_coordinate_restore(response(updated), change=change)
    drifted = dict(updated, q_ref=1)
    with pytest.raises(c.TargetPreservationError):
        c.compile_target_coordinate_restore(response(drifted), change=change, updated=verified)


@pytest.mark.parametrize("field,limit", [("template", 79), ("address", 255), ("domain", 255), ("url", 255)])
def test_coordinates_enforce_conservative_utf8_bounds(field: str, limit: int) -> None:
    value = c.TargetCoordinates("Synthetic", "", "", "")
    with pytest.raises(c.TargetPreservationError): replace(value, **{field: "x" * (limit + 1)})
    with pytest.raises(c.TargetPreservationError): replace(value, **{field: "界" * (limit // 3 + 1)})
    with pytest.raises(c.TargetPreservationError): replace(value, **{field: "bad\nvalue"})


def test_private_objects_do_not_reveal_state_or_support_copy_pickle() -> None:
    _, change, state = prepared()
    for value in (change, state, state.coordinates):
        assert NAME not in repr(value) and "192.0.2" not in str(value)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied): operation(value)
