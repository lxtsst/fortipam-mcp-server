from copy import deepcopy

import pytest

from fortipam_mcp.secret_checkout_effect_contract import (
    CHECKIN_PATH, CHECKOUT_PATH, SecretCheckoutEffectBinding,
    SecretCheckoutEffectContractError, compile_fixed_checkout_effect, fixed_checkout_effect_state,
)

BINDING = SecretCheckoutEffectBinding(17, 9, "synthetic-secret", "synthetic-target", 41, "synthetic-owner")
ROW = {"id": 17, "folder": 9, "name": "synthetic-secret", "target": "synthetic-target",
       "template": "Unix Account (SSH Password)", "associated-secret": 41,
       "target-privilege-account": "disable", "target-info": {"priv_acct": 0},
       "checkout": "enable", "checkout-duration": 5, "checkout-script": "", "checkin-script": "",
       "checkout-duration-renew": "disable", "checkin-pwd-change": "disable",
       "proxy": "enable", "recording": "enable",
       "permissions": {"checkout_status": "required", "passwd_change": "forbidden"},
       "checkout-user": "", "checkout-admin": "", "checkout-time": 0}


def payload(row):
    return {"version": "v7.0.0", "build": 29, "http_status": 200, "http_method": "GET",
            "status": "OK", "path": "secret", "name": "database", "results": row}


def test_native_fixed_requests_and_held_state_never_emit_material_or_selectors():
    before = payload(deepcopy(ROW))
    assert compile_fixed_checkout_effect(before, BINDING, operation="checkout") == (CHECKOUT_PATH, {"secret-id": 17})
    assert fixed_checkout_effect_state(before, BINDING, checked_out=False)
    assert not fixed_checkout_effect_state(before, BINDING, checked_out=True)
    for state in ("checked", "not-renewable"):
        held = deepcopy(ROW); held["permissions"] = {"checkout_status": state, "passwd_change": "allowed"}
        held.update({"checkout-user": "synthetic-owner", "checkout-admin": "synthetic-owner", "checkout-time": 1000})
        held["field"] = [{"value": "synthetic-protected-material"}]
        request = compile_fixed_checkout_effect(payload(held), BINDING, operation="checkin")
        assert request == (CHECKIN_PATH, {"secret-id": 17})
        assert "synthetic-protected-material" not in repr(request)
        assert fixed_checkout_effect_state(payload(held), BINDING, checked_out=True)


@pytest.mark.parametrize("change", [
    {"id": True}, {"id": 18}, {"folder": 10}, {"name": "other"}, {"target": "other"},
    {"associated-secret": True}, {"associated-secret": 42}, {"target-privilege-account": "enable"},
    {"target-info": {"priv_acct": True}}, {"target-info": {"priv_acct": 41}},
    {"checkout-script": "arbitrary-script"}, {"checkin-script": "arbitrary-script"},
    {"checkout-duration-renew": "enable"}, {"checkin-pwd-change": "enable"},
    {"checkout-duration": 6}, {"proxy": "disable"}, {"recording": "disable"},
    {"permissions": {"checkout_status": "waiting", "passwd_change": "forbidden"}},
])
def test_scope_or_effect_prerequisite_drift_is_not_a_request(change):
    with pytest.raises(SecretCheckoutEffectContractError, match="^The fixed Secret checkout effect is unavailable.$"):
        compile_fixed_checkout_effect(payload({**ROW, **change}), BINDING, operation="checkout")


def test_version_envelope_and_unrecognized_operation_fail_closed():
    for change in ({"version": "v1.9.1"}, {"build": True}, {"http_method": "POST"}, {"status": "error"}):
        with pytest.raises(SecretCheckoutEffectContractError):
            compile_fixed_checkout_effect({**payload(ROW), **change}, BINDING, operation="checkout")
    with pytest.raises(SecretCheckoutEffectContractError):
        compile_fixed_checkout_effect(payload(ROW), BINDING, operation="renew")
    assert not fixed_checkout_effect_state(payload(ROW), BINDING, checked_out=1)


@pytest.mark.parametrize("changes", [
    {"checkout-user": "other"}, {"checkout-admin": "other"}, {"checkout-time": True},
    {"checkout-time": 0}, {"checkout-time": -1}, {"checkout-time": 2_147_483_648},
])
def test_held_lease_requires_both_exact_owner_names_and_native_positive_start_time(changes):
    held = {**ROW, "checkout-user": "synthetic-owner", "checkout-admin": "synthetic-owner", "checkout-time": 1000,
            "permissions": {"checkout_status": "not-renewable", "passwd_change": "allowed"}, **changes}
    with pytest.raises(SecretCheckoutEffectContractError):
        compile_fixed_checkout_effect(payload(held), BINDING, operation="checkin")


@pytest.mark.parametrize("changes", [{"checkout-user": "synthetic-owner"}, {"checkout-admin": "synthetic-owner"},
                                    {"checkout-time": 1000}, {"checkout-time": True}])
def test_released_lease_must_have_both_empty_names_and_exact_integer_zero(changes):
    with pytest.raises(SecretCheckoutEffectContractError):
        compile_fixed_checkout_effect(payload({**ROW, **changes}), BINDING, operation="checkout")
