"""JWT editor entitlement is source evidence, never mutation authority."""
from __future__ import annotations

import copy
import hashlib
import json
import pickle

import pytest

from fortipam_mcp import jwt_manual_key_actor_evidence as c
from fortipam_mcp.jwt_manual_key_contract import JwtManualKeyContractError
from v4_planning.material_provider import MaterialAccessDenied

SERIAL = hashlib.sha256(b"SYNTHETIC_SERIAL").hexdigest()


def inputs(group="custom", cfg="read-write", *, super_admin=False):
    role = dict(name="synthetic-role", sysgrp=group, **{"sysgrp-permission": {"cfg": cfg, "mnt": "none"}})
    admin = dict(name="synthetic-api", login_name="synthetic-api", sponsored_group_name="", guest_admin=False,
                 global_admin=True, super_admin=super_admin, profile=copy.deepcopy(role))
    rows = [dict(admin=admin, vdom_mode="", maintenance_mode=dict(mode="disable"), unselected={"private-note": "NEVER_DECODE"}),
            [dict(name="synthetic-api", accprofile="synthetic-role")], [role], dict(mode="disable")]
    return [dict(version="v7.0.0", build=29, serial="SYNTHETIC_SERIAL", http_method="GET", http_status=200,
                 status="success", path="web-ui" if i == 0 else "system", vdom="root",
                 name=("state", "api-user", "accprofile", "maintenance")[i], results=row)
            for i, row in enumerate(rows)]


def consume(values, **changes):
    buffers = [bytearray(json.dumps(value, separators=(",", ":")).encode()) for value in values]
    try:
        result = c.consume_jwt_manual_key_actor_inputs(*buffers, **dict(
            expected_actor="synthetic-api", expected_profile="synthetic-role", serial_digest=SERIAL, **changes))
        return result
    finally:
        assert all(not raw for raw in buffers)


@pytest.mark.parametrize("group,cfg", [("custom", "read-write"), ("read-write", "none")])
def test_native_parent_and_granular_write_permissions_do_not_require_super_admin(group, cfg):
    first = consume(inputs(group, cfg))
    second = consume(inputs(group, cfg, super_admin=True))
    assert first.digest == second.digest and first.serial_digest == SERIAL
    assert "synthetic-api" not in repr(first)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied):
            operation(first)
    with pytest.raises(JwtManualKeyContractError):
        first.digest = "a" * 64


@pytest.mark.parametrize("fault", ["read-parent", "none-parent", "read-granular", "missing-granular",
    "boolean-granular", "unknown-level", "non-global", "boolean-global", "vdom-enabled", "vdom-missing",
    "maintenance-enabled", "maintenance-missing", "state-maintenance-drift", "guest", "sponsored", "login-mismatch", "user-profile-drift",
    "active-profile-drift", "role-drift", "row-name-drift", "missing-user-name", "origin-name-drift", "mkey-drift", "counter-drift",
    "boolean-counter", "limited", "next-page", "duplicate-rows", "missing-state-serial", "foreign-state-serial",
    "foreign-role-serial", "wrong-build", "wrong-http", "backend-error", "schema-error"])
def test_unqualified_or_drifting_inputs_refuse_without_partial_evidence(fault):
    values = inputs()
    admin = values[0]["results"]["admin"]
    active = admin["profile"]
    persisted = values[2]["results"][0]
    if fault in {"read-parent", "none-parent"}:
        active["sysgrp"] = persisted["sysgrp"] = "read" if fault == "read-parent" else "none"
    if fault in {"read-granular", "boolean-granular", "unknown-level"}:
        active["sysgrp-permission"]["cfg"] = persisted["sysgrp-permission"]["cfg"] = {
            "read-granular": "read", "boolean-granular": True, "unknown-level": "write"}[fault]
    if fault == "missing-granular":
        del active["sysgrp-permission"]["cfg"]
    if fault in {"non-global", "boolean-global"}:
        admin["global_admin"] = False if fault == "non-global" else 1
    if fault == "vdom-enabled": values[0]["results"]["vdom_mode"] = "multi-vdom"
    if fault == "vdom-missing": del values[0]["results"]["vdom_mode"]
    if fault == "state-maintenance-drift": values[0]["results"]["maintenance_mode"]["mode"] = "enable"
    if fault == "maintenance-enabled": values[3]["results"]["mode"] = "enable"
    if fault == "maintenance-missing": del values[3]["results"]["mode"]
    if fault == "guest": admin["guest_admin"] = True
    if fault == "sponsored": admin["sponsored_group_name"] = "synthetic-sponsor"
    if fault == "login-mismatch": admin["login_name"] = "synthetic-other"
    if fault == "user-profile-drift": values[1]["results"][0]["accprofile"] = "synthetic-other"
    if fault == "active-profile-drift": active["name"] = "synthetic-other"
    if fault == "role-drift": persisted["sysgrp-permission"]["cfg"] = "read"
    if fault == "row-name-drift": persisted["name"] = "synthetic-other"
    if fault == "missing-user-name": del values[1]["results"][0]["name"]
    if fault == "origin-name-drift": persisted["q_origin_key"] = "synthetic-other"
    if fault == "mkey-drift": values[2]["mkey"] = "synthetic-other"
    if fault in {"counter-drift", "boolean-counter"}: values[2]["matched_count"] = 2 if fault == "counter-drift" else True
    if fault == "limited": values[2]["limit_reached"] = True
    if fault == "next-page": values[2]["next_idx"] = 1
    if fault == "duplicate-rows": values[2]["results"] *= 2
    if fault == "missing-state-serial": del values[0]["serial"]
    if fault == "foreign-state-serial": values[0]["serial"] = "FOREIGN"
    if fault == "foreign-role-serial": values[2]["serial"] = "FOREIGN"
    if fault == "wrong-build": values[3]["build"] = True
    if fault == "wrong-http": values[3]["http_status"] = 500
    if fault == "backend-error": values[3]["error"] = -3
    if fault == "schema-error": values[3]["schema_errors"] = []
    with pytest.raises(JwtManualKeyContractError, match="^The private manual JWT public-key contract is unavailable.$"):
        consume(values)


def test_unselected_actor_content_is_never_scalar_decoded(monkeypatch):
    scalar = c.parser._scalar
    def selected_only(raw, span):
        assert b"NEVER_DECODE" not in raw[slice(*span)]
        return scalar(raw, span)
    monkeypatch.setattr(c.parser, "_scalar", selected_only)
    consume(inputs())


@pytest.mark.parametrize("fault", ["duplicate", "trailing", "interruption"])
def test_framing_failure_and_interruption_erase_every_input(monkeypatch, fault):
    buffers = [bytearray(json.dumps(value).encode()) for value in inputs()]
    if fault == "duplicate": buffers[0] = buffers[0].replace(b'"global_admin": true', b'"global_admin": true, "global_admin": true')
    if fault == "trailing": buffers[2].extend(b"null")
    if fault == "interruption":
        def interrupted(*args, **kwargs): raise KeyboardInterrupt
        monkeypatch.setattr(c.parser, "_scalar", interrupted)
    with pytest.raises(KeyboardInterrupt if fault == "interruption" else JwtManualKeyContractError):
        c.consume_jwt_manual_key_actor_inputs(*buffers, expected_actor="synthetic-api",
            expected_profile="synthetic-role", serial_digest=SERIAL)
    assert all(not raw for raw in buffers)
