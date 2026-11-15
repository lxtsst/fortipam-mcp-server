"""Empty native Secret-session results never supply authority or visibility."""
import hashlib
import json

import pytest

from fortipam_mcp import policy_assignment_session_baseline as module

SERIAL = "FPAVUNIT000001"
SERIAL_DIGEST = hashlib.sha256(SERIAL.encode()).hexdigest()
MARKER = "SYNTHETIC_SESSION_VALUE_MUST_NOT_BE_DECODED"


def response():
    return dict(version="v7.0.0", build=29, path="user", name="proxy-session", action="select",
        http_method="GET", status="success", serial=SERIAL, vdom="root", results=[])


def consume(value):
    raw = bytearray(b"\n " + json.dumps(value).encode() + b"\n")
    try:
        return module.consume_policy_assignment_empty_session_source(raw, serial_digest=SERIAL_DIGEST)
    finally:
        assert not any(raw)


def test_native_empty_array_is_an_opaque_observation_without_global_or_mutation_claims():
    result = consume(response())
    public = result.summary()
    assert public["observed_native_secret_session_result_empty"] is True
    for name in ("global_session_absence_qualified", "actor_visibility_qualified", "source_provenance_qualified",
            "request_absence_qualified", "assignment_authorized"):
        assert public[name] is False
    assert result.observation_digest not in str(public) and SERIAL not in repr(result)
    assert "redacted" in repr(result)


@pytest.mark.parametrize("fault", ["missing", "null", "object", "nonempty", "three-empty-buckets", "device",
    "wrong-route", "wrong-action", "missing-action", "wrong-status", "cursor", "partial-hint", "count"])
def test_other_display_shapes_and_partial_or_unbound_sources_fail_closed(fault, monkeypatch):
    value = response()
    if fault == "missing": del value["results"]
    elif fault == "null": value["results"] = None
    elif fault == "object": value["results"] = {}
    elif fault == "nonempty": value["results"] = [{"tokenid": MARKER}]
    elif fault == "three-empty-buckets": value["results"] = [[], [], []]
    elif fault == "device": value["serial"] = "ANOTHERDEVICE"
    elif fault == "wrong-route": value["path"] = "firewall"
    elif fault == "wrong-action": value["action"] = "deauth"
    elif fault == "missing-action": del value["action"]
    elif fault == "wrong-status": value["status"] = "error"
    elif fault == "cursor": value["next_index"] = 0
    elif fault == "partial-hint": value["has_more"] = False
    elif fault == "count": value["size"] = True
    original = module.metadata._scalar
    def scalar(content, span):
        assert MARKER.encode() not in content[slice(*span)]
        return original(content, span)
    monkeypatch.setattr(module.metadata, "_scalar", scalar)
    with pytest.raises(module.PolicyAssignmentSessionBaselineError) as caught:
        consume(value)
    assert str(caught.value) == module._ERROR


def test_interrupt_clears_the_owned_frame(monkeypatch):
    def interrupted(*_args): raise KeyboardInterrupt
    monkeypatch.setattr(module, "_spans", interrupted)
    with pytest.raises(KeyboardInterrupt): consume(response())
