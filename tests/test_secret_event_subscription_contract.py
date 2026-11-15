from copy import deepcopy
from dataclasses import replace
import json

import pytest

from fortipam_mcp.secret_event_subscription_contract import (
    SecretEventSubscriptionBinding,
    SecretEventSubscriptionContractError,
    compile_fixed_subscription,
    project_subscription_detail,
    project_subscription_portal,
    subscription_readback_matches,
)

BINDING = SecretEventSubscriptionBinding(7, 3, "synthetic-secret", "synthetic-target", "synthetic-owner")
PORTAL = {"name": BINDING.owner_name, "email": ""}
OTHER = {"name": "synthetic-other", "event": "sec-launch"}
ROW = {"id": 7, "folder": 3, "name": BINDING.secret_name,
       "template": "Web Account", "target": BINDING.target_name, "subscriber": [OTHER]}
PAYLOAD = {"version": "v7.0.0", "build": 29, "http_status": 200,
           "http_method": "GET", "status": "OK", "path": "secret",
           "name": "database", "results": ROW}


@pytest.mark.parametrize("failure", [None, "build", "boolean_build", "status", "method", "multiple",
                                    "id", "boolean_id", "folder", "template", "target", "owner",
                                    "email", "unknown_portal", "already_subscribed", "unknown_event",
                                    "duplicate_owner", "duplicate_event", "subscriber_extra", "invalid_operation"])
def test_single_event_compilation_rejects_identity_notification_and_baseline_drift(failure):
    payload, portal, binding, operation = deepcopy(PAYLOAD), dict(PORTAL), BINDING, "subscribe"
    row = payload["results"]
    if failure == "build": payload["build"] = 30
    if failure == "boolean_build": payload["build"] = True
    if failure == "status": payload["status"] = "error"
    if failure == "method": payload["http_method"] = "POST"
    if failure == "multiple": payload["results"] = [row, deepcopy(row)]
    if failure == "id": row["id"] = 8
    if failure == "boolean_id": binding = replace(binding, secret_id=True)
    if failure == "folder": row["folder"] = 4
    if failure == "template": row["template"] = "Windows Machine"
    if failure == "target": row["target"] = "other-target"
    if failure == "owner": portal["name"] = "other-owner"
    if failure == "email": portal["email"] = "test@example.invalid"
    if failure == "unknown_portal": portal["recipient"] = "test@example.invalid"
    if failure == "already_subscribed": row["subscriber"].append({"name":binding.owner_name,"event":"cfg-chg"})
    if failure == "unknown_event": row["subscriber"][0]["event"] = "unknown"
    if failure == "duplicate_owner": row["subscriber"].append(deepcopy(OTHER))
    if failure == "duplicate_event": row["subscriber"][0]["event"] = "sec-launch sec-launch"
    if failure == "subscriber_extra": row["subscriber"][0]["recipient"] = "test@example.invalid"
    if failure == "invalid_operation": operation = "arbitrary"
    original = deepcopy((payload, portal))
    if failure:
        with pytest.raises(SecretEventSubscriptionContractError,
                           match="^The fixed Secret event subscription is unavailable.$"):
            compile_fixed_subscription(payload, portal, binding, operation=operation)
    else:
        assert compile_fixed_subscription(payload, portal, binding, operation=operation) == {
            "secret-id": 7, "event": "cfg-chg"}
        after = deepcopy(payload)
        after["results"]["subscriber"].append({"name":binding.owner_name,"event":"cfg-chg"})
        assert subscription_readback_matches(payload, after, binding, subscribed=True)
        assert compile_fixed_subscription(after, portal, binding, operation="restore") == {
            "secret-id": 7, "event": ""}
        assert compile_fixed_subscription(after, {**portal,"email":"test@example.invalid"},
                                          binding, operation="restore") == {"secret-id":7,"event":""}
        assert subscription_readback_matches(after, payload, binding, subscribed=False)
        removed = deepcopy(payload)
        removed["results"]["subscriber"] = []
        assert not subscription_readback_matches(after, removed, binding, subscribed=False)
        wrong_event = deepcopy(after)
        wrong_event["results"]["subscriber"][-1]["event"] = "pwd-view"
        assert not subscription_readback_matches(payload, wrong_event, binding, subscribed=True)
        assert not subscription_readback_matches(payload, after, binding, subscribed=1)
    assert (payload, portal) == original


def test_projection_skips_unselected_material_before_decoding_and_rejects_duplicate_selection(monkeypatch):
    payload = deepcopy(PAYLOAD)
    payload["results"]["field"] = [{"name":"Password", "value":"SYNTHETIC_MATERIAL_SENTINEL"}]
    payload["results"]["credentials-history"] = ["SYNTHETIC_MATERIAL_SENTINEL"]
    payload["serial"] = "SYNTHETIC_MATERIAL_SENTINEL"
    raw = bytearray(json.dumps(payload).encode())
    loads = json.loads

    def no_material_decode(value, *args, **kwargs):
        assert b"SYNTHETIC_MATERIAL_SENTINEL" not in bytes(value)
        return loads(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", no_material_decode)
    assert project_subscription_detail(raw) == PAYLOAD
    array_payload = deepcopy(payload)
    array_payload["results"] = [array_payload["results"]]
    assert project_subscription_detail(bytearray(json.dumps(array_payload).encode())) == PAYLOAD
    assert project_subscription_portal(bytearray(
        b'{"results":{"name":"synthetic-owner","email":"","token":"SYNTHETIC_MATERIAL_SENTINEL"}}'
    )) == PORTAL
    for invalid in [
        raw + b" {}",
        raw.replace(b'"id": 7', b'"id": 7,"id": 8'),
        raw.replace(b'"results": {', b'"results": [{').replace(b'}}', b'}}]'),
        bytearray(b'{"results":{"name":"synthetic-owner","name":"other","email":""}}'),
        raw.replace(b'"event": "sec-launch"', b'"event": "sec-launch", "password": "SYNTHETIC_MATERIAL_SENTINEL"'),
        raw.replace(b'"event": "sec-launch"', b'"event": {"password": "SYNTHETIC_MATERIAL_SENTINEL"}'),
    ]:
        parser = project_subscription_portal if invalid.startswith(b'{"results"') else project_subscription_detail
        with pytest.raises(SecretEventSubscriptionContractError):
            parser(invalid)
    # No parser mutates the caller's raw buffer; its owner must zeroize it.
    assert raw == bytearray(json.dumps(payload).encode())
