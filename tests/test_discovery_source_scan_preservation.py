from __future__ import annotations

import copy
import hashlib
import json

import pytest

from fortipam_mcp.discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from fortipam_mcp.discovery_entry_create_http_transport import DiscoveryEntryCreateResult
from fortipam_mcp.discovery_entry_projection import DiscoveryEntryReadback
from fortipam_mcp.discovery_run_http_transport import AccountDiscoveryAck, DiscoveryRunResult
from fortipam_mcp.discovery_source_scan_preservation import (
    DiscoverySourcePreservationError, OwnedUnixDiscoveryScanPreservation,
)


SOURCE = DisabledUnixDiscoveryCreateInput("bp014-discovery-unix-disabled-20261024-r900", 17)
ACCOUNT = "fpam-bp014-discovery-r123456789"
STAMP = "2026-10-24 03:04:05"
SCOPE = dict(actor_digest="a" * 64, device_digest=hashlib.sha256(b"SYNTHETIC-DEVICE").hexdigest(), fixture_birth_digest="b" * 64)
CREATED = DiscoveryEntryCreateResult(True, "http_200", 200,
    DiscoveryEntryReadback(True, False, True, True, True, True, True, True, True))
RUN = DiscoveryRunResult("accepted", 200, True, True, account_ack=AccountDiscoveryAck(0, 0))


def payload(scanned: bool = False) -> dict:
    row = {key: value for key, value in SOURCE.body().items() if key != "$originalName"}
    row.update({"q_origin_key": SOURCE.source_name, "last-discovery-time": STAMP if scanned else "0000-00-00 00:00:00",
        "discovery-results": [{"name": ACCOUNT, "managed-status": 0, "last-scanned-time": STAMP, "q_origin_key": ACCOUNT}] if scanned else [],
        "additional-native-state": {"flag": "keep", "values": [1, True, None]}})
    return dict(status="success", http_method="GET", http_status=200, path="secret", name="discovery",
        vdom="root", version="v7.0.0", build=29, serial="SYNTHETIC-DEVICE", results=[row])


def witness(**kwargs) -> OwnedUnixDiscoveryScanPreservation:
    return OwnedUnixDiscoveryScanPreservation(SOURCE, ACCOUNT, **SCOPE, creation=kwargs.get("creation", CREATED),
        original_source=kwargs.get("original_source", payload()), key=bytearray(b"K" * 32))


def test_full_scan_delta_and_original_scope_are_preserved_without_authority():
    before, after = payload(), payload(True)
    original = copy.deepcopy((before, after))
    pin = witness()
    result = pin.accept_completed_scan(after, RUN, **SCOPE)
    assert result["original_configuration_preserved"] is True
    assert result["source_recovery_authorized"] is result["latest_run_or_timezone_qualified"] is False
    assert pin.inspect_accepted_scan(after, **SCOPE) == result
    assert (before, after) == original
    public = json.dumps(result) + repr(pin)
    assert ACCOUNT not in public and SOURCE.source_name not in public and "additional-native-state" not in public
    with pytest.raises(DiscoverySourcePreservationError):
        pin.accept_completed_scan(after, RUN, **SCOPE)
    pin.close()
    assert not pin._key
    with pytest.raises(DiscoverySourcePreservationError):
        pin.inspect_accepted_scan(after, **SCOPE)


def test_native_readback_representation_is_pinned_independently_of_post_serializer():
    before, after = payload(), payload(True)
    # Synthetic readback differences model normalized disabled-feature fields;
    # these values do not claim to reproduce the exact native seven-field set.
    normalized = {"accprofiles": [], "group-filters": [], "discovery-sch-month-day": 1,
        "discovery-sch-week-day": [], "discovery-sch-month-type": "day",
        "discovery-sch-start-date": "2026-10-24", "login-method": "username-password"}
    for response in (before, after): response["results"][0].update(copy.deepcopy(normalized))
    pin = witness(original_source=before)
    assert pin.accept_completed_scan(after, RUN, **SCOPE)["original_configuration_preserved"] is True
    pin.close()
    for field in normalized:
        pin = witness(original_source=before)
        drift = copy.deepcopy(after); drift["results"][0][field] = {"changed": True}
        with pytest.raises(DiscoverySourcePreservationError): pin.accept_completed_scan(drift, RUN, **SCOPE)
        pin.close()


@pytest.mark.parametrize("field,value", [
    ("owner", "changed"), ("schedule-status", "enable"), ("auto-onboarding", "enable"),
    ("discovery-secret", 18), ("discovery-password", "SYNTHETIC-FORBIDDEN"),
    ("additional-native-state", {"flag": "changed"}), ("unexpected-field", "new"),
    ("last-discovery-time", "0000-00-00 00:00:00"), ("discovery-results", []),
])
def test_scan_rejects_all_other_changes_or_missing_completion(field, value):
    pin = witness()
    after = payload(True)
    after["results"][0][field] = value
    with pytest.raises(DiscoverySourcePreservationError, match="unavailable"):
        pin.accept_completed_scan(after, RUN, **SCOPE)
    pin.close()


@pytest.mark.parametrize("run", [
    DiscoveryRunResult("accepted", 200, False, True),
    DiscoveryRunResult("ambiguous", 200, True, True),
    DiscoveryRunResult("accepted", 403, True, True),
    DiscoveryRunResult("accepted", 200, True, False),
    DiscoveryRunResult("accepted", 200, True, True, True),
])
def test_timestamp_and_review_cannot_replace_verified_original_run_result(run):
    pin = witness()
    with pytest.raises(DiscoverySourcePreservationError):
        pin.accept_completed_scan(payload(True), run, **SCOPE)
    pin.close()


@pytest.mark.parametrize("ack", [None, AccountDiscoveryAck(1, 0), AccountDiscoveryAck(0, 1)])
def test_scanned_boolean_cannot_replace_explicit_native_account_reply_counts(ack):
    pin = witness()
    run = DiscoveryRunResult("accepted", 200, True, True, account_ack=ack)
    with pytest.raises(DiscoverySourcePreservationError):
        pin.accept_completed_scan(payload(True), run, **SCOPE)
    pin.close()


@pytest.mark.parametrize("defect", ["actor", "device", "fixture", "serial", "managed", "different_account", "duplicate_account", "nested_drift"])
def test_binding_and_accepted_snapshot_drift_are_denied(defect):
    pin = witness()
    after = payload(True)
    scope = dict(SCOPE)
    if defect in {"actor", "device", "fixture"}:
        key = {"actor": "actor_digest", "device": "device_digest", "fixture": "fixture_birth_digest"}[defect]
        scope[key] = "c" * 64
    elif defect == "serial":
        after["serial"] = "SYNTHETIC-OTHER-DEVICE"
    elif defect == "managed":
        after["results"][0]["discovery-results"][0]["managed-status"] = 1
    elif defect == "different_account":
        after["results"][0]["discovery-results"][0]["name"] = "other-account"
    elif defect == "duplicate_account":
        after["results"][0]["discovery-results"] *= 2
    else:
        pin.accept_completed_scan(after, RUN, **SCOPE)
        after["results"][0]["additional-native-state"]["values"].append(2)
        with pytest.raises(DiscoverySourcePreservationError):
            pin.inspect_accepted_scan(after, **SCOPE)
        pin.close()
        return
    with pytest.raises(DiscoverySourcePreservationError):
        pin.accept_completed_scan(after, RUN, **scope)
    pin.close()


@pytest.mark.parametrize("creation", [
    DiscoveryEntryCreateResult(True, "ambiguous", 200, CREATED.readback),
    DiscoveryEntryCreateResult(False, "http_200", 200, CREATED.readback),
    DiscoveryEntryCreateResult(True, "http_200", 200, None),
])
def test_birth_requires_original_unambiguous_successful_creation(creation):
    with pytest.raises(DiscoverySourcePreservationError):
        witness(creation=creation)
