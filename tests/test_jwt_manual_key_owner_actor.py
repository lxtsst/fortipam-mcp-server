"""Local Owner evidence cannot substitute for JWT backend authority."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import pickle

import pytest

from fortipam_mcp import jwt_manual_key_owner_actor as c
from fortipam_mcp.jwt_manual_key_contract import JwtManualKeyContractError
from v4_planning.material_provider import MaterialAccessDenied

SERIAL = hashlib.sha256(b"SYNTHETIC_SERIAL").hexdigest()
OWNER = "synthetic-owner"


def sources():
    admin = {"name": OWNER, "login_name": OWNER, "guest_admin": False,
             "sponsored_group_name": "", "global_admin": True, "super_admin": True,
             "profile": {"name": "super_admin", "sysgrp": "read-write", "secretgrp": "read-write"}}
    state = {"admin": admin, "vdom_mode": "", "maintenance_mode": {"mode": "disable"},
             "unselected": {"note": "NEVER_DECODE"}}
    user = [{"name": OWNER, "q_origin_key": OWNER, "accprofile": "super_admin",
             "status": "enable", "remote-auth": "disable", "wildcard": "disable"}]
    common = {"version": "v7.0.0", "build": 29, "serial": "SYNTHETIC_SERIAL",
              "http_method": "GET", "http_status": 200, "status": "success", "vdom": "root"}
    before = {**common, "path": "web-ui", "name": "state", "results": state}
    local = {**common, "path": "system", "name": "admin", "mkey": OWNER, "results": user}
    return [before, local, deepcopy(before)]


def consume(values, **changes):
    buffers = [bytearray(json.dumps(value).encode()) for value in values]
    now = datetime.now(timezone.utc)
    options = {"expected_owner": OWNER, "serial_digest": SERIAL,
               "first_device_date": now, "last_device_date": now}
    options.update(changes)
    try:
        return c.consume_jwt_manual_key_owner_actor_inputs(*buffers, **options)
    finally:
        assert all(not raw for raw in buffers)


def test_stable_local_owner_is_opaque_and_grants_no_write():
    evidence = consume(sources())
    assert OWNER not in repr(evidence)
    assert evidence.summary() == {"contract": c.CONTRACT,
        "bracketed_local_super_admin_context_matched": True,
        "source_provenance_authenticated": False,
        "jwt_backend_write_permission_qualified": False, "execution_authorized": False}
    assert not hasattr(evidence, "credentials") and not hasattr(evidence, "permit")
    with pytest.raises(JwtManualKeyContractError):
        evidence.digest = "changed"
    with pytest.raises(MaterialAccessDenied):
        pickle.dumps(evidence)


@pytest.mark.parametrize("fault", ["api-user", "non-super", "boolean-super", "non-global",
    "profile", "system-readonly", "secret-readonly", "maintenance", "vdom", "guest", "sponsor",
    "owner", "mapping-name", "mapping-profile", "disabled", "remote", "wildcard", "foreign-device",
    "mkey", "second-actor", "second-permission", "duplicate-row", "paging", "counter", "build"])
def test_qualified_editor_or_drift_does_not_become_owner_context(fault):
    values = sources(); admin = values[0]["results"]["admin"]; row = values[1]["results"][0]
    if fault == "api-user": values[1]["name"] = "api-user"
    if fault == "non-super": admin["super_admin"] = False
    if fault == "boolean-super": admin["super_admin"] = 1
    if fault == "non-global": admin["global_admin"] = False
    if fault == "profile": admin["profile"]["name"] = "synthetic-other"
    if fault == "system-readonly": admin["profile"]["sysgrp"] = "read"
    if fault == "secret-readonly": admin["profile"]["secretgrp"] = "read"
    if fault == "maintenance": values[0]["results"]["maintenance_mode"]["mode"] = "enable"
    if fault == "vdom": values[0]["results"]["vdom_mode"] = "multi-vdom"
    if fault == "guest": admin["guest_admin"] = True
    if fault == "sponsor": admin["sponsored_group_name"] = "synthetic-sponsor"
    if fault == "owner": admin["login_name"] = "synthetic-other"
    if fault == "mapping-name": row["name"] = "synthetic-other"
    if fault == "mapping-profile": row["accprofile"] = "synthetic-other"
    if fault == "disabled": row["status"] = "disable"
    if fault == "remote": row["remote-auth"] = "enable"
    if fault == "wildcard": row["wildcard"] = "enable"
    if fault == "foreign-device": values[1]["serial"] = "FOREIGN"
    if fault == "mkey": values[1]["mkey"] = "synthetic-other"
    if fault == "second-actor": values[2]["results"]["admin"]["name"] = "synthetic-other"
    if fault == "second-permission": values[2]["results"]["admin"]["profile"]["secretgrp"] = "read"
    if fault == "duplicate-row": values[1]["results"] *= 2
    if fault == "paging": values[1]["next_idx"] = 1
    if fault == "counter": values[1]["matched_count"] = True
    if fault == "build": values[2]["build"] = True
    with pytest.raises(JwtManualKeyContractError):
        consume(values)


@pytest.mark.parametrize("fault", ["stale", "future", "reversed", "long-window", "naive"])
def test_dates_must_be_fresh_ordered_and_bounded(fault):
    now = datetime.now(timezone.utc); first = last = now
    if fault == "stale": first = last = now - timedelta(minutes=6)
    if fault == "future": first = last = now + timedelta(minutes=6)
    if fault == "reversed": first = now + timedelta(seconds=1)
    if fault == "long-window": first = now - timedelta(seconds=61)
    if fault == "naive": first = now.replace(tzinfo=None)
    with pytest.raises(JwtManualKeyContractError):
        consume(sources(), first_device_date=first, last_device_date=last)


def test_actual_ordered_dates_are_bound_to_distinct_observations():
    now = datetime.now(timezone.utc)
    first = consume(sources(), first_device_date=now, last_device_date=now)
    second = consume(sources(), first_device_date=now, last_device_date=now + timedelta(seconds=1))
    assert first.actor_digest == second.actor_digest
    assert first.mapping_digest == second.mapping_digest
    assert first.observation_digest != second.observation_digest and first.digest != second.digest


def test_unselected_material_is_not_scalar_decoded(monkeypatch):
    original = c.parser._scalar
    def selected_only(raw, span):
        assert b"NEVER_DECODE" not in raw[slice(*span)]
        return original(raw, span)
    monkeypatch.setattr(c.parser, "_scalar", selected_only)
    assert consume(sources()).summary()["bracketed_local_super_admin_context_matched"]


def test_interruption_consumes_all_buffers(monkeypatch):
    buffers = [bytearray(json.dumps(value).encode()) for value in sources()]
    def interrupted(*args, **kwargs): raise KeyboardInterrupt
    monkeypatch.setattr(c.parser, "_scalar", interrupted)
    now = datetime.now(timezone.utc)
    with pytest.raises(KeyboardInterrupt):
        c.consume_jwt_manual_key_owner_actor_inputs(*buffers, expected_owner=OWNER,
            serial_digest=SERIAL, first_device_date=now, last_device_date=now)
    assert all(not raw for raw in buffers)
